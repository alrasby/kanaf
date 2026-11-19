#!/usr/bin/env python3
"""Summarize actual Android reports without treating incomplete scans as clean."""
import json
import sys
from pathlib import Path
from measure_host import metrics

def summarize(report, manifest, apk_only=False):
    assert report['complete'] and report['self_test_passed']
    assert report['sample_execution'] is False
    expected = {r['sha256']: r for r in manifest['samples']}
    assert len(expected) == len(manifest['samples']) == 120
    actual = {r['sha256']: r for r in report['cases']}
    assert len(actual) == len(report['cases']) == 120
    assert expected.keys() == actual.keys()
    engines = ('clamav', 'yara_x', 'hash', 'combined')
    counts = {e: {label: dict(matched=0, unmatched=0, incomplete=0)
                  for label in ('benign', 'malicious')} for e in engines}
    for sha, row in actual.items():
        assert row['label'] == expected[sha]['label']
        assert row['group'] == expected[sha]['group']
        if apk_only and not expected[sha]['zip_has_android_manifest']:
            continue
        kinds = []
        for engine in engines[:-1]:
            kind = row[engine]['kind']
            assert kind in ('matched', 'unmatched', 'incomplete')
            counts[engine][row['label']][kind] += 1
            kinds.append(kind)
        # Conservative coverage summary; any known threat wins, otherwise all
        # engines must complete for NoKnownMatch. Input hashes were asserted by
        # the Android harness. This is not a substitute for UI consensus tests.
        combined = 'matched' if 'matched' in kinds else 'incomplete' if 'incomplete' in kinds else 'unmatched'
        counts['combined'][row['label']][combined] += 1
    return dict(platform=report['platform'], counts=counts, metrics=metrics(counts),
                certification=False, label_authority='External source labels, not independently re-adjudicated')

if __name__ == '__main__':
    report = json.loads(Path(sys.argv[1]).read_text())
    manifest = json.loads(Path(sys.argv[2]).read_text())
    result = summarize(report, manifest)
    result['apk_only'] = summarize(report, manifest, apk_only=True)
    Path(sys.argv[3]).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['counts'], indent=2))
