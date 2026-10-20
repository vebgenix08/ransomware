# RansomShield implementation status

Updated 2026-10-20. “Implemented” means present and locally tested. It does not mean production-certified or validated against live ransomware.

| Area | Status | Current behavior and remaining work |
|---|---|---|
| Accounts and dashboard | Implemented | Flask authentication, CSRF, account-owned run history, incident reports |
| Directory monitoring | Implemented locally; remote agent added | Watches `MONITOR_TARGET_PATH`; an opt-in Windows agent can forward VM event summaries over HTTPS into the same rolling 30-second burst rules. Process attribution is unavailable; the activity score is heuristic, not a malware probability. |
| TCN + XGBoost telemetry model | Offline CSV only | Frozen artifact is trained on synthetic sequences and does not drive live folder alerts. Replace it with independently sourced, labeled endpoint telemetry before using it for detection claims. |
| MLRan evaluation | Implemented locally | Separate tabular XGBoost model on published MLRan data; sampling limitations apply. |
| SILRAD Sysmon evaluation | Implemented locally | Setup script downloads SILRAD's separate train/test files into ignored `instance/`, trains a project-specific hashed-text XGBoost model on 39,999 training events, then evaluates 156,841 held-out events. Fixed-threshold recall is 10.17% (17,543 false negatives); benchmark only, unsuitable for live alerts. |
| Dataset analysis | Implemented | Compatible CSV formats, ownership, metrics, hashes, reports; CSV paths are not used to modify local files. |
| Automated response | Audit-only for live alerts | Live burst alerts never move files because change volume alone does not establish malware. Dataset analysis also never moves local files. |
| Notifications | Configured locally | Gmail SMTP settings stored in ignored `.env`; real delivery still requires a successful live message check. Mock tests do not validate Gmail. |
| SFTP transfer | Implemented locally | Sender/receiver checksum validation and idempotency tests pass; a physical two-laptop transfer remains unverified. |
| PWA | Implemented | Install manifest, root-scoped service worker, static asset cache, offline page. Authenticated data and API responses are not cached. |
| Production endpoint protection | Not complete | Needs real labeled data, process attribution, independent validation, HTTPS deployment, configured PostgreSQL/backups, durable jobs, and incident recovery testing. A VM agent is now available but requires an HTTPS host and an actual VM connection test. |

## Safety and evaluation policy

- Uploaded dataset runs only create analysis and incident records. Their CSV paths are never used as filesystem paths.
- Live monitoring is limited to the configured directory and uses a 30-second heuristic burst policy. Alerts still can be false positives or misses; a high-volume benign update can cross the thresholds.
- The synthetic-trained telemetry model is used only for offline telemetry CSV evaluation. It and the MLRan tabular model have different schemas and are not interchangeable.
- MLRan scores describe the included dataset only. They do not establish prospective endpoint performance.
- Email status `sent` means SMTP accepted the message; it is not an inbox delivery receipt.

## Verification

Run the local suite with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests cover authentication, model inference, dataset validation, user ownership, report generation, response auditing, quarantine restore, SFTP integrity handling, and PWA routes. Mocked SMTP tests are not live-delivery verification.
