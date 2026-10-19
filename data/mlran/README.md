# Published MLRan integration

Source: https://github.com/faithfulco/mlran/tree/main/6_experiments/FS_MLRan_Datasets

Citation: Onwuegbuche, Faithful Chiagoziem; Adelodun, Sunday Olaoluwa;
Jurcut, Anca Delia; Pasquale, Liliana (2025). MLRan: A Behavioural Dataset
for Ransomware Analysis and Detection. https://arxiv.org/abs/2505.18613

Downloaded public CSV feature records on 2026-10-14. No executable samples were
downloaded. The publisher README states MIT licensing, but the linked LICENSE
file returned 404 at acquisition; no missing license text is fabricated here.

Original files contain 3,905 training and 975 test rows with 483 binary features.
The application trains on 202 API/FILE/DIRECTORY/REG/DROP features. Sample IDs,
all label columns, and SIGNATURE/STRING/SYSTEM domains are excluded from training.
Exact duplicate vectors are collapsed; contradictory-label groups are removed;
test vectors present anywhere in original training are removed from evaluation.
Final counts: 2,300 training and 324 held-out samples (229 benign, 95 ransomware).

`heldout.csv` is the derived evaluation CSV accepted by the dashboard and sender.
`training_report.json` records hashes, parameters, cleaning counts and metrics:
accuracy 92.90%, precision 85.29%, recall 91.58%, F1 88.32%; TP 87, TN 214,
FP 15, FN 8. No threshold tuning on the held-out labels was performed.

This is a separate tabular XGBoost model. It is not a TCN evaluation, a
family-disjoint evaluation, or a prospective real-world result. Publisher feature
preselection and environment/collection bias remain limitations. The existing
TCN + XGBoost model remains trained on synthetic ordered telemetry.

Reproduce from project root:

```powershell
.\.venv\Scripts\python.exe scripts/train_mlran.py
```
