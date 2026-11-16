# Kanaf AI URL-only empirical pilot

**Purpose:** Make the offline URL lexical risk model actually trainable, signed,
loaded, and tested on an Android emulator. This is **not** the APK malware ML
model (`VerifiedLinearThreatModel`) and does not replace antivirus signatures.

**Dataset:** Arvind Prasad and Shalini Chandra, *PhiUSIIL Phishing URL Dataset*,
Mendeley Data v2 (2023), DOI `10.17632/shwpxscxy2.2`, CC BY 4.0.
UCI dataset #967: https://archive.ics.uci.edu/dataset/967/
Source CSV contains 235,795 URL records (original labels **0=phishing,
1=legitimate**). The trainer inverts these labels exactly once. Derivative
work: only 12 URL-text lexical features and a small logistic regression model.
Training reads URL strings but **NEVER sends a request to those URLs**.

**Evaluation:** Dataset is split deterministically into 70/15/15 by
approximate registrable domain group; exact URL duplicates rejected from
multiple splits. Numeric features only use URL text; never page HTML or site
reputation. Training-only normalization is folded into 12 final coefficients.
The threshold is selected on the validation split and evaluated on an untouched
within-dataset held-out split. See the training artifact `evaluation.json`
for the actual AUC, precision-recall, FPR and recall; do not substitute
published accuracy from other models. The group logic is an approximation of
the public suffix list and **not** an external-source independent benchmark.
Labels are historical: modern phishing and compromised legitimate sites can
behave differently, and the fitted values are NOT calibrated real-world risk.

**Security:** GitHub Actions uses an ephemeral RSA private key only inside
the training step; it is deleted before APK build and never published. The
debug APK contains signed model bytes and the corresponding public verification
key. The runtime refuses missing, malformed or unsigned models. No UI action
uploads, visits, or follows any scanned URLs. The model only runs on a
user-entered/shared link, offers an advisory score, and cannot mark it safe.
The production APK/antivirus `main` workflow ships no experimental URL
model or ephemeral key by default. Do not deploy the pilot APK to Play.

**Reproduce**: GitHub workflow `.github/workflows/kanaf-url-ai-pilot.yml`
downloads and trains from the **original** CC BY 4.0 dataset and runs
`KanafUrlAiAndroidTest` with the signed model. Its archive and source CSV
digests are recorded in the `evaluation.json` artifact, which includes
no raw URLs. Dataset drift or an incorrect class mapping is never silently
replaced by synthetic examples.

**Still required for production APK malware AI**: A separately licensed,
label-reviewed Android APK corpus with the same 7 features extracted from
actual APKs, independent cross-source holdouts, family/drift/fairness
validation, calibration, physical-device resource testing, offline publisher
key management, malware feed coverage and Play compliance.
