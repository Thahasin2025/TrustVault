# Deployment and operations checklist

This is a preparation checklist, not evidence of a deployed or production-ready
system. Select a hosting provider, domain, and accountable operator before
deployment. Validate the plan in a separate staging environment first.

## Before deployment

1. Run `python -m pip install -r requirements-test.txt` and `python -m pytest`.
   Test the migration and role workflows against an isolated MySQL database and
   through a browser. Never use the existing audit database as a test fixture.
2. Provision MySQL with a dedicated, least-privilege application account, a
   private network, encryption and managed backups. Secure uploaded files
   outside the web root and provide persistent storage.
3. Store strong, distinct JWT and audit HMAC keys in the platform's secret
   manager. Preserve historical audit keys securely for verification and plan
   rotation. Never place keys, `.env`, uploads, or database backups in Git.
4. Configure HTTPS at a trusted reverse proxy, restrict network access, and
   test the application through the public origin. The proxy must route both
   the frontend and API paths to this application on the same origin. Configure
   and validate CORS if cross-origin access is required; the current CORS
   allowlist is for local development.
5. Add edge rate limiting and monitoring, and decide on malware scanning. The
   built-in login throttle and file signature checks do not replace these.
6. Choose a protected, independently retained audit-anchor strategy and test
   database, upload, anchor and historical-key backup and recovery together.
   The current application writes a local anchor after database commit; a
   write failure can leave the anchor out of sync and requires investigation.
7. Back up and preserve the existing audit records and anchor before any
   migration or recovery. Follow `THREATS.md` for the known invalid history;
   never silently rewrite or re-sign it.
8. Apply `python -m backend.migrate_security_features` only after testing the
   migration and confirming backups. Create the initial admin through the
   documented CLI. Start the application under a supervised service with a
   restricted user; do not use development reload in production.

## Verification and incident response

Check the admin dashboard, role authorization, document access/revocation,
restore, purge, audit verification, monitoring and backups in staging. Record
results, restore a backup in isolation, and obtain operational sign-off before
serving real users. Alert on failed audit verification, failed anchor writes,
backup failures, storage capacity, application errors, and login abuse.

If verification fails, preserve the database, anchor, configuration and logs;
restrict access and investigate the reported reason. A hash failure does not
by itself establish tampering, and a valid suffix does not validate an earlier
failed prefix. Do not rewrite history to make the dashboard show success.
