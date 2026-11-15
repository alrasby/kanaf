import unittest
from train_apk_risk_model import require_independence

class TrainingReleaseSafetyTest(unittest.TestCase):
    @staticmethod
    def record(identifiers, collections):
        # No numpy or training dataset required for data-leakage regression.
        return (None, None, set(identifiers), set(collections))

    def test_disjoint_hashes_and_collection_groups(self):
        require_independence((
            self.record(["a"], ["upstream-2021"]),
            self.record(["b"], ["upstream-2022"]),
            self.record(["c"], ["upstream-2023"]),
        ))

    def test_duplicate_apk_across_splits_blocks_release(self):
        with self.assertRaisesRegex(ValueError, "share APK"):
            require_independence((
                self.record(["a"], ["batch-1"]),
                self.record(["a"], ["batch-2"]),
                self.record(["b"], ["batch-3"]),
            ))

    def test_shared_data_collection_blocks_release(self):
        with self.assertRaisesRegex(ValueError, "share source"):
            require_independence((
                self.record(["a"], ["source-1"]),
                self.record(["b"], ["source-1"]),
                self.record(["c"], ["source-3"]),
            ))

if __name__ == "__main__":
    unittest.main()
