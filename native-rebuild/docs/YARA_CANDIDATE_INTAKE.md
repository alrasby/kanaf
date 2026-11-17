# YARA candidate staging — not production approval

External candidate source: https://github.com/Neo23x0/signature-base
Default source license: Detection Rule License (DRL) 1.1, with individual rule exceptions.
Matching alerts and redistributed files must attribute the specified rule author.

Use a clean upstream Git checkout at an explicitly pinned 40-digit SHA.
Create a local JSON plan with schema=1, upstream=Neo23x0/signature-base,
commit=<pinned SHA>, license_sha256=<actual license digest>, and a rules list.
Each entry specifies path=yara/<selected name>.yar, sha256=<file digest>,
author=<exact meta author>. Pin and review every rule before using the tool.

From native-rebuild:
    python3 tools/prepare_yara_candidates.py --source /tmp/signature-base \
      --plan /tmp/publisher-review.json --out /tmp/kanaf-yara-candidates

The output is deliberately UNREVIEWED_CANDIDATE_ONLY. It is NOT copied
to Android assets. Each rule still needs compilation against pinned YARA-X
0.13.0, appropriate benign and malicious independent tests, review of false
positives and licensing, author attribution in displayed detections, and
signature/publisher approval. Avoid claiming EICAR tests prove real protection.

After staging a candidate, record a separately labeled local APK corpus
in UTF-8 TSV with columns `sha256` and `label` (`benign` or `malicious`).
Name each input `<sha256>.apk`. With `yara-x==0.13.0` installed, run:

    python3 tools/evaluate_yara_candidates.py candidate.yar corpus.tsv /local/corpus

The report fingerprints the inputs and counts hits, misses, and incomplete
scans separately. It measures rules against raw APK bytes, so rules that
require extracted archive entries need a separate evaluation and matching
Android scan support. A corpus with either label missing is partial.
