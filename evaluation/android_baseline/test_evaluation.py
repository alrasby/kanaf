import json
import unittest
from pathlib import Path
from measure_host import metrics, wilson
from summarize_results import summarize

class EvaluationIntegrityTest(unittest.TestCase):
    def test_zero_observed_false_alarms_does_not_mean_zero_population_rate(self):
        interval = wilson(0, 60)
        self.assertAlmostEqual(0.06017185214208986, interval[1])
        self.assertEqual(0, interval[0])

    def test_incomplete_scans_are_excluded_from_completed_denominator(self):
        result = metrics({'engine': {'malicious': dict(matched=2, unmatched=3, incomplete=5)}})['engine']['malicious']
        self.assertEqual(5, result['completed'])
        self.assertEqual(0.4, result['match_rate_completed'])
        self.assertEqual([0.2, 0.7], result['all_input_match_rate_bounds'])

    def test_all_incomplete_is_undefined_rate(self):
        result = metrics({'engine': {'benign': dict(matched=0, unmatched=0, incomplete=10)}})['engine']['benign']
        self.assertIsNone(result['match_rate_completed'])
        self.assertIsNone(result['wilson_95_completed'])

    def test_actual_manifest_has_no_duplicates_or_training_hash_overlap(self):
        here = Path(__file__).parent
        manifest = json.loads((here/'corpus-manifest.json').read_text())
        samples = manifest['samples']
        self.assertEqual(120, len({r['sha256'] for r in samples}))
        self.assertEqual(60, sum(r['label']=='benign' for r in samples))
        self.assertEqual(60, sum(r['label']=='malicious' for r in samples))
        self.assertEqual([], manifest['acquisition_failures'])
        self.assertEqual([], manifest['conflicting_labels'])
        assets = here.parents[1]/'native-rebuild/app/src/main/assets/production_clamav.hsb'
        learned = {s.split(':')[0] for s in assets.read_text().splitlines()}
        self.assertFalse(learned & {r['sha256'] for r in samples})

    def test_android_summary_rejects_partial_or_duplicate_report(self):
        manifest = {'samples':[dict(sha256=str(i),label='benign',group='test') for i in range(120)]}
        verdicts = dict(hash={'kind':'unmatched'},clamav={'kind':'incomplete'},yara_x={'kind':'unmatched'})
        report = dict(complete=True,self_test_passed=True,sample_execution=False,platform='test',
            cases=[dict(row,**verdicts) for row in manifest['samples']])
        result = summarize(report, manifest)
        self.assertEqual(120, result['counts']['combined']['benign']['incomplete'])
        report['cases'][-1] = report['cases'][0]
        with self.assertRaises(AssertionError):
            summarize(report, manifest)

    def test_non_apk_collector_files_do_not_inflate_apk_recall(self):
        manifest = json.loads((Path(__file__).parent/'corpus-manifest.json').read_text())
        no_match = dict(hash={'kind':'unmatched'},clamav={'kind':'unmatched'},yara_x={'kind':'unmatched'})
        report = dict(complete=True,self_test_passed=True,sample_execution=False,platform='test',
            cases=[dict(row,**no_match) for row in manifest['samples']])
        result = summarize(report, manifest, apk_only=True)
        self.assertEqual(54, result['metrics']['combined']['malicious']['total'])
        self.assertEqual(60, result['metrics']['combined']['benign']['total'])

if __name__ == '__main__':
    unittest.main()
