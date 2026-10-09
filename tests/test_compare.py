import random
import unittest
from probekit.compare import python_similarity, similarity


class CompareTests(unittest.TestCase):
    def test_known_scores(self):
        self.assertEqual(similarity(b"", b""), 1)
        self.assertEqual(similarity(b"a", b"b"), 0)
        self.assertAlmostEqual(similarity(b"abcd", b"abce"), 1 / 3)
        self.assertEqual(similarity(b"\0\0\0", b"\0\0\0"), 1)

    def test_native_and_fallback_agree_on_binary_data(self):
        rng = random.Random(1234)
        for _ in range(100):
            left = rng.randbytes(rng.randrange(2000))
            right = left[:len(left)//2] + rng.randbytes(rng.randrange(1000))
            self.assertAlmostEqual(similarity(left, right), python_similarity(left, right))
