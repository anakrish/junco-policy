import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


class BenchmarkPageTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "report").mkdir()
        (self.root / "report/index.html").write_text("plots", encoding="utf-8")
        self.files = {}
        for history in (1025, 16385, 65537):
            for workload, param, values in (("refund_stream", "aborted", (0, 16)),
                                            ("binding_churn", "bindings", (16, 17, 32))):
                for value in values:
                    for engine in ("junco", "dogwood"):
                        key = f"{workload}/{engine}/history_{history}/{param}_{value}"
                        path = self.root / str(len(self.files)) / "new"
                        path.mkdir(parents=True)
                        self.files[key] = path / "benchmark.json"
                        elements = value if param == "bindings" else 32
                        self.files[key].write_text(json.dumps({"full_id": key, "throughput": {"Elements": elements}}))
                        point = 34000 if engine == "junco" else 51000
                        bounds = {"confidence_level": 0.95, "lower_bound": point - 17000, "upper_bound": point + 17000}
                        (path / "estimates.json").write_text(json.dumps({"mean": {"point_estimate": point, "confidence_interval": bounds}}))

    def render(self):
        return subprocess.run([sys.executable, Path(__file__).with_name("dogwood_bench_page.py"), self.root],
                              capture_output=True, text=True)

    def test_overlapping_means_per_decision(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        html = (self.root / "index.html").read_text(encoding="utf-8")
        rows = [re.findall(r"<td>(.*?)</td>", row) for row in re.findall(r"<tr>(.*?)</tr>", html, re.S)]
        row, = (row for row in rows if row[:2] == ["65,537", "17"])
        self.assertEqual(row[2:5], ["2.000 [1.000, 3.000]", "3.000 [2.000, 4.000]", "1.50×"])
        self.assertIn("inconclusive", row[5])
        self.assertIn("Junco lower", row[5])

    def assert_rejected(self, key):
        result = self.render()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(key, result.stderr)
        self.assertFalse((self.root / "index.html").exists())

    def test_missing_engine(self):
        key = "refund_stream/dogwood/history_1025/aborted_0"
        self.files[key].unlink()
        self.assert_rejected(key)

    def test_wrong_elements(self):
        key = "binding_churn/junco/history_65537/bindings_17"
        self.files[key].write_text(json.dumps({"full_id": key, "throughput": {"Elements": 16}}))
        self.assert_rejected(key)
