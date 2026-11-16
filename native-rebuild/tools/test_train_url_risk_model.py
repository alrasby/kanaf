import math
import unittest
from train_url_risk_model import lexical_features, split_of, registrable_group, LABEL_MAPPING

class URLPilotTrainerTest(unittest.TestCase):
    def test_reversed_original_phiusiil_labels(self):
        self.assertEqual(LABEL_MAPPING["0"], 1)
        self.assertEqual(LABEL_MAPPING["1"], 0)

    def test_feature_vector_matches_android_reference(self):
        f = lexical_features("https://example.com/a?b=1")
        self.assertEqual(len(f), 12)
        self.assertAlmostEqual(f[5], math.log1p(2))
        self.assertEqual(f[7:10], [1., 0., 0.])
        self.assertAlmostEqual(f[2], math.log1p(1))

    def test_invalid_input_fails_closed(self):
        for url in ["javascript:alert(1)", "https://", "https://مثال.اختبار",
                    "https://example.com/" + "a" * 2100]:
            self.assertIsNone(lexical_features(url))

    def test_split_disjoint_for_same_registered_domain(self):
        group = registrable_group("https://login.account.example.com/a")
        self.assertEqual(group, registrable_group("https://example.com/b"))
        self.assertEqual(split_of(group), split_of(registrable_group(
            "http://example.com/anything")))
        self.assertIn(split_of(group), ("train", "val", "test"))

if __name__ == "__main__":
    unittest.main()
