# RansomShield project information audit

**Reviewed:** 20 October 2026

**Purpose:** Current-state reference for the checked-in application. Historical design notes and old test results are not treated as evidence of current behavior.

## What the application does

RansomShield is a Flask research prototype with account-based access, a dashboard, a local SQLite database by default, a directory activity monitor, labeled CSV evaluation, alert records, email/webhook adapters, CSV reports, SFTP transfer utilities, and installable PWA assets.

It has two separate analysis paths:

1. **Live directory monitor:** watches only the configured `MONITOR_TARGET_PATH`. It observes file creates, changes, and deletes, then raises review alerts using rolling 30-second burst thresholds. Its activity score is a heuristic, not a probability or ransomware verdict. Live alerts do not automatically move files.
2. **Offline dataset evaluation:** the dashboard trains a project-specific event-level XGBoost model on SILRAD's training split and evaluates its separate test split. Legacy MLRan and synthetic-telemetry CSV APIs remain, but are not the dashboard benchmark workflow. Dataset evaluation does not inspect the computer or move files named in a CSV.

## Comparison with the supplied methodology

The supplied ten-step methodology describes the intended design. It is not an accurate description of the live application yet:

| Methodology step | What the application does now |
|---|---|
| 1. Initialize Flask and database | Implemented locally. SQLite is the default. |
| 2. Monitor a decoy server | Partially implemented: monitors one configured directory. The app does not currently build the described Finance/HR decoy server or seed canary files. |
| 3–4. Collect telemetry and extract 11 features | Partially implemented: live monitoring counts file creates/changes/deletes and reads basic host metrics. It does not currently assemble and save the complete 11-feature labeled sequence for live model inference. |
| 5–7. TCN, XGBoost, probability threshold | Not used for live alerts. The synthetic-trained TCN + XGBoost runs only on compatible offline telemetry CSVs. The live monitor uses burst-count rules. The methodology's 0.60 model threshold is not the live alert policy. |
| 8. Generate alerts | Implemented: live burst rules and CSV evaluations can create alert records and configured notifications. These alerts indicate review-worthy activity or flagged dataset rows, not confirmed infection. |
| 9. Quarantine files | Not active in current live or CSV workflows. Supporting quarantine/restore code exists, but current workflows do not move files. |
| 10. Log and notify | Implemented locally: records are stored in the configured database; email/webhook attempts are optional and must be tested with the installer's own settings. |

In plain terms: **live folder monitoring is rules → alert → review. CSV analysis is validated rows → matching model → report/optional alert.** The live path does not currently run TCN/XGBoost or quarantine files.

The supplied model metrics remain results on the named test datasets. The synthetic TCN result is not real endpoint evidence. The MLRan result is a published-data benchmark, not proof that the live monitor detects ransomware.

## Current capabilities and limits

| Area | Current state |
|---|---|
| Authentication | Flask local accounts are supported. Firebase Authentication is optional and requires each installation's Firebase web config and trusted Firebase Admin credentials. |
| Storage | SQLite is the default local database. PostgreSQL migration/deployment is not configured by this repository's default setup. |
| Live monitoring | Local single-process monitor; configured directory only; burst rules; no process attribution and no validated malware classification. |
| Published data | Included cleaned MLRan evaluation set has 324 held-out samples, 95 ransomware and 229 benign. Its benchmark metrics describe that set only. |
| Telemetry ML | Offline CSV evaluation only. The model is synthetic-trained; this is not real endpoint validation. |
| SILRAD Sysmon events | A separate local-only train/test workflow uses SILRAD's published split and a project-specific hashed-text XGBoost model. Current fixed 0.60 test recall is 10.17% (17,543 false negatives); it is a weak benchmark model and is not connected to live monitoring. |
| Response | Live monitor alerts and dataset alerts do not quarantine files. Email/webhook `sent` status means provider acceptance, not confirmed delivery/read. |
| SFTP | Sender and receiver have local automated coverage. Transfer between physical laptops has not been verified. |
| PWA | Manifest, service worker, static-asset cache and offline page are present. Authenticated pages, API responses, uploads and incident evidence are not cached. |
| Deployment | `run.py` binds locally; this is not production hosting. Production endpoint protection is not complete. |

## Dataset and upload guidance

The dashboard benchmark uses the two SILRAD CSV splits prepared by `scripts/setup_silrad.py`; it does not use VM telemetry as a labeled ransomware sample. The app does not currently collect process-attributed endpoint traces or create malware labels for the user. Do not upload private or sensitive telemetry until retention and access policies are defined.

For a first functional check, run the included published MLRan held-out dataset from the dashboard. This validates the local CSV/model/report workflow using published records; it does not test live monitoring or prove real-world detection. A user-provided CSV is useful only when its provenance, labels, and schema are known.

## Configuration and privacy

- Copy `.env.example` to a local `.env`; the local file is ignored by Git. Use each installer's own SMTP, Firebase, database, and webhook settings.
- Do not commit `.env`, service-account JSON, SMTP app passwords, OAuth secrets, or database passwords.
- The Firebase browser config is project-specific and public-facing; the Admin credential is private and must stay in a secret store or ignored local directory.
- Never put a user's real credentials in project documentation, screenshots, tests, or source control. Rotate any password exposed outside a private credential store.

## Verification

The automated suite covers authentication, model/schema behavior, ownership, reports, notification outcomes with mocks, response auditing, SFTP integrity handling, and PWA routes. A passing mocked suite does not establish live email delivery, physical transfer, external model validity, or production readiness. See `README.md` for the local test command and workflow.

## Known documentation boundary

`papers/RansomShield_IEEE_Paper.tex`, the generated PowerPoint, and its generator include older experimental design/results. They must be reviewed against the current implementation before being presented as a description of today's application. The public landing page, `README.md`, `ROADMAP.md`, and this audit are the current operational descriptions.
