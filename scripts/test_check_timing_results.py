import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("timing", Path(__file__).with_name("check-timing-results.py"))
timing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing)

class TimingResultsTests(unittest.TestCase):
    def report(self, first="+1.20", second="-2.3"):
        return f"bench timing_hmac_verify ... : n == +0.100M, max t = {first}, max tau = 0.1\nbench timing_key_unwrap ... : n == +0.100M, max t = {second}, max tau = 0.1\n"

    def test_valid_results(self):
        self.assertEqual(timing.check(self.report()), [])

    def test_seed_announcements_are_not_measurements(self):
        seeds = "bench timing_hmac_verify seeded with 0x1234\nbench timing_key_unwrap seeded with 0xabcd\n"
        self.assertEqual(timing.check(seeds + self.report()), [])
        self.assertTrue(timing.check(seeds))

    def test_cropped_population_is_not_total_sample_count(self):
        self.assertEqual(timing.check(self.report().replace("+0.100M", "+0.001M")), [])

    def test_missing_result(self):
        self.assertTrue(timing.check(self.report().splitlines()[0]))

    def test_bad_measurements_fail(self):
        for value in ("NaN", "inf", "-inf", "garbage", "-4.51", "5e1"):
            with self.subTest(value=value):
                self.assertTrue(timing.check(self.report(value)))

    def test_duplicate_failure_is_not_hidden(self):
        self.assertTrue(timing.check(self.report("9") + self.report()))

if __name__ == "__main__":
    unittest.main()
