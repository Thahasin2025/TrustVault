# Backlog

## Admin dashboard and auditing

- [ ] Investigate the historical audit verification failure documented in
  [THREATS.md](THREATS.md). Recover the original signing key from a protected
  backup if available and verify the preserved chain. Do not rewrite, delete,
  truncate, or re-sign the existing records; historical authenticity remains
  unproven until verification succeeds.
- [x] Install the test dependencies and run the automated suite (15 passed on
  2026-11-08, using Python 3.9 and isolated SQLite databases).
- [x] In an isolated browser and SQLite database, check admin login, dashboard,
  activity, successful audit verification and saved verification display.
- [ ] Exercise admin account changes, authorization denial, and failed audit
  verification in a browser.
- [ ] Test the security migration and audit verification against MySQL,
  including concurrent audit appends and backup/anchor recovery. SQLite tests
  alone do not establish MySQL behavior.
- [ ] Design independent, protected storage and recovery for the audit anchor;
  the current local anchor is not independent of the application host.
- [ ] Address the audit anchor write occurring after database commit: an anchor
  write failure can leave the committed chain and anchor out of sync. Define
  monitoring and a safe recovery procedure before production use.
- [ ] Consider changing the verification action from GET to POST because it
  saves the latest result, with a compatibility plan for existing API clients.
- [ ] Add pagination or filtering for audit activity if administrators need
  access beyond the latest 500 events.

## Integration, deployment and project records

- [x] Run the test suite from a clean copy without the local `.env`; all 15
  tests passed on 2026-11-08 using an isolated test signing key.
- [ ] Make a dedicated MySQL test database available and run migration,
  concurrency and integration tests without altering the existing audit data.
- [x] Using isolated test data, check Owner and Viewer registration, Owner
  login/upload/share, Viewer login/shared listing, and Viewer denial of
  download and admin APIs (403).
- [ ] Complete browser testing of Viewer document viewing, access revocation,
  and the remaining Admin scenarios described above. The browser automation
  click did not submit the registration form, while native `requestSubmit()`
  did; this does not establish a manual-click defect.
- [x] Use the serving origin for frontend API requests so the application can
  run behind a same-origin HTTPS proxy without targeting localhost.
- [ ] Choose a deployment target and complete the staging and production
  prerequisites in [the operations checklist](documentation/OPERATIONS.md).
- [ ] Have the project owner review the pending confirmations in `PROMPTS.md`
  and review the existing working-tree changes before committing them.
