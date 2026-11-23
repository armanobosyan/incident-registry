import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import build  # noqa: E402

HEADER = ",".join(build.COLUMNS)
ROW = "2024-07-19,Example system,outage,Something broke.,,,none,confirmed,https://example.org/a,"


def csv_text(*rows):
    return "\n".join([HEADER, *rows]) + "\n"


class LoadRows(unittest.TestCase):
    def test_a_good_row_loads(self):
        rows = build.load_rows(csv_text(ROW))
        self.assertEqual(rows[0]["organisation_system"], "Example system")

    def test_a_month_or_a_year_is_a_date(self):
        rows = build.load_rows(csv_text(ROW.replace("2024-07-19", "2024"), ROW.replace("2024-07-19", "2024-07")))
        self.assertEqual([r["date"] for r in rows], ["2024", "2024-07"])

    def test_header_must_match(self):
        with self.assertRaisesRegex(build.RegistryError, "header"):
            build.load_rows("date,name\n2024-01-01,x\n")

    def test_bad_values_are_refused(self):
        cases = {
            "not YYYY-MM-DD": ROW.replace("2024-07-19", "19 Jul 2024"),
            "YYYY-MM or YYYY": ROW.replace("2024-07-19", "2024-13"),
            "type": ROW.replace(",outage,", ",storm,"),
            "ai_link": ROW.replace(",none,", ",maybe,"),
            "evidence": ROW.replace(",confirmed,", ",rumour,"),
            "https": ROW.replace("https://example.org/a", "http://example.org/a"),
            "long dash": ROW.replace("Something broke.", "Something " + chr(0x2014) + " broke."),
            "milestone": ROW.replace(",outage,", ",milestone,"),
        }
        for message, row in cases.items():
            with self.subTest(message), self.assertRaisesRegex(build.RegistryError, message):
                build.load_rows(csv_text(row))

    def test_order_and_duplicates(self):
        later = ROW.replace("2024-07-19", "2025-01-01")
        with self.assertRaisesRegex(build.RegistryError, "date order"):
            build.load_rows(csv_text(later, ROW))
        with self.assertRaisesRegex(build.RegistryError, "twice"):
            build.load_rows(csv_text(ROW, ROW))

    def test_empty_registry(self):
        with self.assertRaisesRegex(build.RegistryError, "no rows"):
            build.load_rows(csv_text())


class Meta(unittest.TestCase):
    def test_version_follows_the_date(self):
        ok = build.load_meta('{"data_version": "20261118", "as_of": "2026-11-18"}')
        self.assertEqual(ok["data_version"], "20261118")
        with self.assertRaisesRegex(build.RegistryError, "as_of date"):
            build.load_meta('{"data_version": "20261117", "as_of": "2026-11-18"}')
        with self.assertRaisesRegex(build.RegistryError, "eight digits"):
            build.load_meta('{"data_version": "2026111801", "as_of": "2026-11-18"}')


class RealData(unittest.TestCase):
    def test_the_committed_registry_is_valid_and_built(self):
        rows = build.load_rows(build.CSV_PATH.read_text(encoding="utf-8"))
        meta = build.load_meta(build.META_PATH.read_text(encoding="utf-8"))
        payload = build.build_payload(rows, meta)
        self.assertEqual(build.OUT_PATH.read_text(encoding="utf-8"), build.render(payload))
        counts = payload["counts"]
        self.assertEqual(counts["cases"], sum(counts["by_role"].values()))
        self.assertEqual(counts["cases"] + counts["milestones"], len(payload["rows"]))
        self.assertEqual(json.loads(build.render(payload))["rows"], rows)


if __name__ == "__main__":
    unittest.main()
