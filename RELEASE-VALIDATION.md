# SCC 0.6.0 implementation and validation report

## Changes in this archive
- Bumped application and Compose image version from 0.5.0 to 0.6.0.
- Added persistent SQLite global storage quota configuration.
- Added per-user nullable storage quota column through a non-destructive migration.
- Added storage ownership metadata table. Existing files remain unknown until reconciliation.
- Added Root_user-only storage status, global quota, per-user quota, and reconciliation API routes.
- Added global and per-user quota controls to the existing owner user-management view.
- Added upload-time global and per-user quota checks and records ownership for completed uploads.
- Extended the `scc` CLI with `general-max`, `user-max`, `storage-status`, and `storage-reconcile`.
- Updated README and SECURITY documentation with CLI usage and explicit limitations.

## Validation actually performed
- Python syntax compilation of `backend/app/main.py`: PASS.
- Bash syntax validation of `management/scc`: PASS.
- Bash syntax validation of `install-scc.sh`: PASS.
- Node syntax validation of `backend/app/static/app.js`: PASS.
- pytest: NOT RUN — collection failed because `pwdlib` is not installed in this execution environment. Network access was unavailable, so the pinned backend requirements could not be installed.
- Docker Compose validation and container tests: NOT RUN — Docker CLI/Engine is unavailable in this execution environment.
- ZIP extraction and SHA-256 verification: performed during packaging (see release verification below).

## Important remaining limitations — this is not a complete security certification
- The quota lock is process-local; multiple workers/replicas are not safe for strict atomic quota enforcement.
- User quota enforcement is currently implemented for uploads, not every storage-increasing operation (text creation, edits, copies, archive extraction, or other future endpoints).
- Accounting is not yet transactionally coupled to every filesystem mutation. Reconciliation is available and preserves known ownership, but external writers and crash windows can create temporary discrepancies.
- The frontend exposes quota configuration controls, but does not yet render a complete per-user/global live usage meter with remaining bytes and utilization percentages.
- The CLI's storage status reports configured limits; the application API provides live global usage. The CLI reconciliation walks the configured host root and updates the ownership index.
- Docker isolation settings were inspected and retained; no Docker runtime validation was possible. Existing Compose does not apply an outbound network policy or hard filesystem project quota.
- The requested full adversarial security test matrix, concurrent multi-process testing, and staging upgrade test were not executable here.

Do not treat this release as satisfying all requirements in the SCC hardening request. Review the limitations above and test on a staging Linux host before production rollout.
