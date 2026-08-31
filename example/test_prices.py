"""The suite that guards `src/prices.py` — one real test and one hollow one."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from prices import label, total  # noqa: E402


class Prices(unittest.TestCase):
    def test_total(self):
        self.assertEqual(total([{"price": 2, "quantity": 3}]), 6)

    def test_label_runs(self):
        # A HOLLOW TEST, deliberately. It calls `label` and asserts nothing about what
        # it returns, so no change to `label` can ever make it fail. Finding that out
        # is what `canfail` is for.
        label("ada")


if __name__ == "__main__":
    unittest.main()
