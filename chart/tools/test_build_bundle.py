import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from chart.tools.build_bundle import build_bundle, read_rules


class BuildChartBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.chart_dir = Path(__file__).resolve().parents[1]

    def test_source_rules_are_valid(self) -> None:
        rules = read_rules(self.chart_dir)

        self.assertEqual(["official.target-sdk-35-plus"], [rule["id"] for rule in rules])

    def test_bundle_is_deterministic_and_contains_only_expected_files(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_manifest = build_bundle(self.chart_dir, Path(first), 1)
            second_manifest = build_bundle(self.chart_dir, Path(second), 1)

            self.assertEqual(first_manifest, second_manifest)
            with zipfile.ZipFile(Path(first) / "chart.bundle") as archive:
                self.assertEqual(
                    ["catalog.json", "icons/android-15.svg"],
                    archive.namelist(),
                )
                catalog = json.loads(archive.read("catalog.json"))
            self.assertEqual(1, catalog["schemaVersion"])
            self.assertEqual(1, len(catalog["definitions"]))


if __name__ == "__main__":
    unittest.main()
