import hashlib
import json
import unittest
from evaluate_model import evaluate, auc_roc


def fixture(prefix, i, label, split, score=None):
    row = {
        "sha256": hashlib.sha256(f"{prefix}-{i}".encode()).hexdigest(),
        "split": split, "source": prefix + "_set", "label": label
    }
    if score is not None:
        row["score"] = score
    return json.dumps(row)


class OfflineMlReadinessTest(unittest.TestCase):
    def test_auc_handles_rankings_and_ties(self):
        self.assertEqual(auc_roc([
            {"label": 0, "score": 0.1}, {"label": 1, "score": 0.8}
        ]), 1)
        self.assertEqual(auc_roc([
            {"label": 0, "score": 0.5}, {"label": 1, "score": 0.5}
        ]), 0.5)

    def test_small_synthetic_test_fixture_never_approves_production(self):
        rows = [
            fixture("train", 0, 0, "train"),
            fixture("external", 0, 0, "holdout", 0.1),
            fixture("external", 1, 1, "holdout", 0.9)
        ]
        result = evaluate(rows)
        self.assertEqual(result["auc"], 1.0)
        self.assertFalse(result["passes_math_gate"])

    def test_duplicate_hashes_are_rejected(self):
        item = fixture("same", 0, 0, "train")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evaluate([item, item])

    def test_source_leakage_and_missing_training_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "source-level"):
            evaluate([
                fixture("same", 0, 0, "train"),
                fixture("same", 1, 1, "holdout", 0.9)
            ])
        with self.assertRaisesRegex(ValueError, "training"):
            evaluate([fixture("external", 1, 1, "holdout", 0.9)])

    def test_bad_scores_and_labels_are_rejected(self):
        train = [fixture("train", 0, 0, "train")]
        with self.assertRaisesRegex(ValueError, "score"):
            evaluate(train + [fixture("external", 0, 1, "holdout", float("nan"))])
        wrong = json.loads(fixture("external", 0, 0, "holdout", .1))
        wrong["label"] = True
        with self.assertRaisesRegex(ValueError, "split or label"):
            evaluate(train + [json.dumps(wrong)])


if __name__ == "__main__":
    unittest.main()
