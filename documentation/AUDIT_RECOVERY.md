# Audit anchor and recovery plan

This plan is not an implemented independent anchor. Production use requires an
independently administered, durable store and a tested integration.

## Independent checkpoint design

An external checkpoint service should accept a signed chain head containing the
database identity, last event ID and hash, and a checkpoint timestamp. Store
each checkpoint as a new immutable version in a separate account with retention
protection. The application identity may append checkpoints but must not be
able to delete or shorten retention. A separate operator controls retention,
reads and recovery. Alert on missing checkpoints, rejected writes and a head
that does not match the latest independently retained checkpoint. Protect the
signing keys separately and retain historical verification keys across rotation.

The database commit and an external write cannot be made atomic by a local file
replacement. A durable transactional outbox and a single ordered publisher can
record checkpoint work with the audit event, retry delivery, and expose lag and
failures. The publisher must not advance or overwrite a checkpoint out of order.
Until this is implemented and tested, the existing local anchor is not an
independent checkpoint and a committed event may lack a corresponding anchor.

## Anchor failure or mismatch

1. Alert an operator and restrict further writes while preserving the database,
   anchor, application logs, configuration and any external checkpoints.
2. Record the last independently trusted checkpoint and obtain a consistent,
   protected copy of the database and anchor for investigation. Do not delete,
   rewrite, re-sign or silently replace audit records or checkpoints.
3. Verify the signed checkpoint and all chain links and record hashes from the
   beginning using the appropriate current and historical verification keys.
   Compare the trusted checkpoint with the corresponding database record and
   identify any subsequent committed events. A valid suffix alone cannot
   authenticate an invalid prefix.
4. Investigate missing keys, corruption, transaction failures and possible
   tampering. Document evidence and obtain an independent operator's approval
   before any recovery action. Do not automatically advance a stale anchor;
   doing so could hide a rollback or alteration.
5. Restore service only after the cause is understood, a recovery procedure has
   been reviewed, and verification and monitoring have been tested on a copy.
   If authenticity cannot be established, retain the failure as an unresolved
   incident and do not claim that the historical chain is valid.

## Historical key recovery

Search only authorized secret managers and protected backups for the original
audit signing key or the JWT secret used when the records were signed. Never
print keys in logs or commit them to the repository. Supply recovered keys via
the protected `AUDIT_HMAC_VERIFY_KEYS` configuration and verify a preserved copy
first. A matching key may authenticate unchanged records; failure does not prove
which of a missing key, changed data or another cause is responsible.
