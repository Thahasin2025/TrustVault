# PROMPTS.md — AI assistance log

| Date | Prompt (summary) | What I used / changed |
|------|------------------|-----------------------|
| 2026-11-02 | [CONFIRM] Asked for initial project setup and database connection/schema initialization. | Used `backend/database.py`, `backend/init_db.py`, `.gitignore`, `documentation/`. (Add what you checked or changed yourself.) |
| 2026-11-02 | Asked to show the actual user in Recent system activity after successful login. | Used audit logging and activity display code; corrected the fixture-name assertion in `test/test_document_workflow.py`. (Add what you checked or changed yourself.) |
| 2026-11-03 | Asked for document search and request auditing across the frontend and API. | Used `frontend/dashboard.html`, `backend/main.py`, `test/test_document_workflow.py`. (Add what you checked or changed yourself.) |
| 2026-11-03 | [CONFIRM] Asked for the TrustVault frontend. | Used `frontend/index.html`, `frontend/dashboard.html`, `frontend/script.js`, `frontend/style.css`. (Add what you checked or changed yourself.) |
| 2026-11-04 | [CONFIRM] Asked for administrator creation and supporting tests. | Used `backend/create_admin.py`, `backend/add_admin.py`, `requirements.txt`, `test/test_admin_password_reset.py`. (Add what you checked or changed yourself.) |
| 2026-11-04 | Asked to review security requirements, add protections and tests, update threat documentation, and avoid deployment. | Used `backend/main.py`, `backend/audit.py`, `backend/login_throttle.py`, `backend/models.py`, `test/test_document_workflow.py`, `THREATS.md`. (Add what you checked or changed yourself.) |
| 2026-11-05 | Asked to complete document deletion/purge behavior and setup/API documentation. | Used `backend/main.py`, `backend/models.py`, `backend/migrate_security_features.py`, `frontend/dashboard.html`, `test/test_document_workflow.py`, `README.md`, `requirements.txt`. (Add what you checked or changed yourself.) |
| 2026-11-06 | Asked to investigate audit-chain verification and preserve the existing unverifiable records. | Used `backend/audit.py`, `backend/main.py`, `frontend/dashboard.html`, `test/test_audit_integrity.py`, `THREATS.md`. (Add what you checked or changed yourself.) |
| 2026-11-06 | Asked to invalidate administrator tokens after password reset. | Used `backend/auth.py`, `backend/models.py`, `backend/reset_admin.py`, `backend/migrate_security_features.py`, `test/test_admin_password_reset.py`. (Add what you checked or changed yourself.) |
| 2026-11-06 | Asked to diagnose repeated login throttling without weakening brute-force protection. | Used `backend/login_throttle.py`, `backend/main.py`, `test/test_document_workflow.py`. (Add what you checked or changed yourself.) |
| 2026-11-06 | Asked to explain the audit verification failure without rewriting audit history. | Reviewed `backend/audit.py`, `test/test_audit_integrity.py`, `frontend/dashboard.html`; no audit records or anchor were changed. (Add what you checked or changed yourself.) |
| 2026-11-07 | Asked to check a frontend runtime error while the app was running. | Reviewed `frontend/index.html`, `frontend/script.js`, `README.md`; started the API for the check. Browser page load had no runtime/console errors. (Add what you checked or changed yourself.) |
| 2026-11-07 | Asked to verify the threat table's implementation and test references against the code. | Reviewed `backend/main.py`, `backend/audit.py`, `backend/login_throttle.py`, `backend/auth.py`, `backend/database.py`, frontend code, and tests; updated `THREATS.md` only. (Add what you checked or changed yourself.) |
| 2026-11-07 | [CONFIRM] Asked for private upload storage and an AI assistance log. | Used `uploads/`, `backend/main.py`, `backend/models.py`, `PROMPTS.md`, `test/test_document_workflow.py`. (Add what you checked or changed yourself.) |
| 2026-11-07 | Asked to format this file as an AI assistance log. | Used `PROMPTS.md`; supplied the reference format. (Add what you checked or changed yourself.) |

Run pytest locally to confirm the tests pass; tests were not run by the AI.
