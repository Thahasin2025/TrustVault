# TrustVault

TrustVault is a document-sharing application built around backend authorization,
per-document permissions, private file storage, and a tamper-evident audit
trail. It uses FastAPI, SQLAlchemy, MySQL, JWT bearer authentication, and a
browser frontend served by the API.

## Features and role permissions

| Role | Capabilities |
|---|---|
| Owner | Upload/manage owned documents, search, view, download, restore or purge own deleted files, and grant/update/revoke named Viewer permissions. |
| Viewer | List documents shared with them; view, edit metadata, and download only when the corresponding current per-document permissions allow it. |
| Admin | Manage account roles/status and inspect/verify audit events. Admin role alone does not grant document-content access. |

These are API-enforced controls. The dashboard hides role-inapplicable controls
for usability only; it is not the authorization boundary.

## Installation and setup

1. Install Python and run these commands from the repository root:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

2. Create a MySQL database and configure a root `.env` file with:

   ```text
   DB_USER=...
   DB_PASSWORD=...
   DB_HOST=127.0.0.1
   DB_PORT=3306
   DB_NAME=trustvault
   JWT_SECRET=<private random secret>
   JWT_ALGORITHM=HS256
   ACCESS_TOKEN_EXPIRE_MINUTES=30
   AUDIT_HMAC_KEY=<optional separate private key, at least 32 bytes>
   AUDIT_HMAC_VERIFY_KEYS=<optional old audit keys, separated by semicolons>
   AUDIT_ANCHOR_PATH=<optional protected path>
   ```

   Keep secrets private. `AUDIT_HMAC_KEY` falls back to `JWT_SECRET` if
   omitted. `AUDIT_HMAC_VERIFY_KEYS` lets the verifier validate records signed
   with previous audit keys; it never signs new records. Add only securely
   recovered historical keys, separated by semicolons, and restart the API.
   The anchor defaults to `uploads/.audit-anchor`.

3. Apply/create the database schema:

   ```powershell
   .\.venv\Scripts\python.exe -m backend.migrate_security_features
   ```

   The migration creates missing tables, adds security columns including
   `users.auth_version` and `documents.purged_at`, and adds the unique
   document/Viewer permission constraint. It also creates the
   `audit_verifications` table and its nullable details column used to retain
   the latest integrity check and data-derived record breakdown.
   It stops if duplicate permission
   rows need manual review. For an existing audit chain, it verifies the
   legacy chain before anchoring it. If verification fails, investigate the
   warning rather than claiming the old history is valid. `backend.init_db`
   is a basic `create_all` helper; it does not replace the security migration
   for existing databases.

4. If there is no administrator, provision one through the interactive CLI:

   ```powershell
   .\.venv\Scripts\python.exe -m backend.create_admin
   ```

   Admins cannot be created through public registration. Additional local
   admin creation and password reset are available via
   `backend.add_admin` and `backend.reset_admin`.

5. Start the API and frontend from the repository root:

   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
   ```

   Open `http://127.0.0.1:8000/`. Do not open frontend HTML using `file://`.
   Register separate Owner and Viewer accounts to exercise sharing.

## API reference

All authenticated endpoints use `Authorization: Bearer <access_token>`.
Tokens are obtained from `POST /login`; `POST /logout` revokes the current
token, and an administrator password reset invalidates all previously issued
tokens for that administrator. Unauthorized requests are denied by the backend.

| Method and path | Access |
|---|---|
| `POST /register`, `POST /login` | Public; registration only accepts Owner or Viewer roles. |
| `GET /me`, `POST /logout` | Any authenticated active user. |
| `GET /users/viewers` | Owner. |
| `POST /documents/upload`, `GET /documents/mine` | Owner; list contains only their active documents. |
| `GET /documents/shared-with-me` | Viewer; only currently shared readable documents. |
| `GET /documents/{id}/view` | Owner or Viewer with current read permission. |
| `GET /documents/{id}/download` | Owner or Viewer with current download permission. |
| `PATCH /documents/{id}` | Owner or Viewer with current edit permission. |
| `DELETE /documents/{id}` | Owner of an active document; moves it to the Recycle Bin and denies later access. |
| `GET /documents/recycle-bin` | Owner; lists only their deleted documents. |
| `POST /documents/{id}/restore` | Owner of a deleted document whose file has not been purged. |
| `POST /documents/{id}/purge` | Owner of a deleted document; removes its active storage file, retains a metadata tombstone and audit history. |
| `POST /documents/{id}/share` | Owner of the document; grants/updates a named Viewer’s per-document permissions. |
| `DELETE /documents/{id}/share/{viewer_user_id}` | Owner of the document; revokes that Viewer’s permission. |
| `GET /documents/{id}/activity` | Owner of the document. |
| `GET /admin/dashboard`, `/admin/audit-logs`, `/admin/audit-logs/verify`, `/admin/users` | Admin only; no document content access. |
| `PATCH /admin/users/{user_id}` | Admin only; account role/status management, with protections against self-lockout and removing the final active admin. |

`{id}` is the numeric document ID returned by upload/list APIs. Access checks
use the authenticated user and current database permission; do not use client
supplied user IDs as authorization evidence.
Name, owner, category, and upload-date filters are applied by the dashboard to
the authenticated user's document list; they are not server-side search APIs.

## Deletion and retention policy

`DELETE /documents/{id}` moves the document into the Owner's Recycle Bin. This
immediately removes it from normal listing and denies view/download/restore
access to other users, but is reversible and retains the private file.
`POST /documents/{id}/purge` is an explicit, irreversible Owner action for a
Recycle Bin item. It unlinks the active file from private storage, clears its
stored path, retains a database metadata tombstone for audit foreign keys, and
records a `DOCUMENT_FILE_PURGED` event. Purging is not secure overwrite:
filesystem snapshots, backups, storage media, and forensic copies may retain
data. Those require a separately managed backup retention and disposal policy.
The Recycle Bin UI identifies purged items and does not offer restore.

## Security behavior and limitations

Each document request validates the token and checks current ownership or
per-document permission on the backend. Revocation affects subsequent
requests; bytes already delivered or an already-authorized in-flight stream
cannot be recalled. Files are stored outside the static frontend directory
using random names, and upload request bodies are capped before multipart
parsing. Files are limited to 10 MB and checked for allowed extension, content
signature, and declared MIME consistency. Allowed extensions are `.pdf`,
`.jpg`, `.jpeg`, `.png`, and `.txt`. There is no malware scanner or full
format parser.

Failed login attempts are limited to 5 per account/direct-IP pair (reset after
a successful login) and 20 per direct IP in 15 minutes. Successful logins no
longer consume the direct-IP failure limit. A distributed attack using many IPs
still needs edge-level limiting; direct peer IP is used, not untrusted
forwarded headers. When a limit is reached, the login response includes the
remaining wait in seconds and a `Retry-After` header.

Audit records are HMAC chained and append-only through the application ORM.
The signed chain-head anchor is local to the application host; a privileged
attacker controlling the database and host/key/anchor can rewrite it. This is
tamper-evident, not absolutely immutable. Admin audit endpoints are protected
by backend role checks. See [THREATS.md](./THREATS.md) for threat scenarios,
tests, and accepted risks.

The configured database's existing history currently fails verification at
audit record 3. Do not treat that history as verified. No audit record or
anchor was changed during the investigation; the evidence and safe recovery
constraints are documented in [THREATS.md](./THREATS.md).

## Automated tests

Run the suite from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-test.txt
.\.venv\Scripts\python.exe -m pytest
```

The workflow tests use isolated SQLite databases and temporary upload
directories; the production configuration is MySQL. SQLite tests do not
replace a MySQL migration/integration test or browser-based verification.

## Project documentation

- [THREATS.md](./THREATS.md): mitigations, test mapping, and residual risks.
- [BACKLOG.md](./BACKLOG.md): remaining verification and deployment work.
- [Operations checklist](./documentation/OPERATIONS.md): staging, deployment,
  backup and audit incident-response prerequisites.
- [PROMPTS.md](./PROMPTS.md): dated AI-use record; commit references remain
  pending until the project owner creates commits.
