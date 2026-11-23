"""Validate data/registry.csv and build public/registry.v1.json.

    python tools/build.py           validate, then write the payload
    python tools/build.py --check   validate, then fail if the committed payload is stale

Standard library only.
"""
import csv
import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "data" / "registry.csv"
META_PATH = ROOT / "data" / "meta.json"
OUT_PATH = ROOT / "public" / "registry.v1.json"

COLUMNS = [
    "date", "organisation_system", "type", "what_happened", "impact", "cause",
    "ai_link", "evidence", "source_url", "second_source_url",
]
TYPES = {
    "outage": "Outage",
    "breach": "Breach",
    "attack": "Attack",
    "supply_chain": "Supply chain",
    "vulnerability": "Vulnerability",
    "research": "Research",
    "milestone": "Milestone",
}
ROLES = {
    "none": "Not AI",
    "ai_direct": "AI the cause",
    "ai_around": "AI around it",
    "ai_found": "AI found it",
    "milestone": "Milestone",
}
EVIDENCE = {"confirmed", "reported"}
DASHES = (chr(0x2013), chr(0x2014))


class RegistryError(ValueError):
    pass


def _date(value, where, full=False):
    """YYYY-MM-DD, or YYYY-MM or YYYY when a source gives only the month or the year."""
    padded = {4: value + "-01-01", 7: value + "-01", 10: value}.get(len(value))
    if full and len(value) != 10:
        padded = None
    try:
        datetime.date.fromisoformat(padded or "")
    except ValueError:
        raise RegistryError(f"{where}: date {value!r} is not YYYY-MM-DD, YYYY-MM or YYYY") from None


def _url(value, where, required):
    if not value:
        if required:
            raise RegistryError(f"{where}: source_url is empty")
        return
    if not value.startswith("https://") or any(c.isspace() for c in value):
        raise RegistryError(f"{where}: {value!r} is not an https URL")


def load_rows(text):
    """Parse and check the CSV text. Returns the rows as dicts, in file order."""
    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames != COLUMNS:
        raise RegistryError(f"header must be {','.join(COLUMNS)}")
    rows = []
    seen = set()
    last = ""
    for n, row in enumerate(reader, start=2):
        where = f"line {n}"
        if None in row or any(v is None for v in row.values()):
            raise RegistryError(f"{where}: wrong number of fields")
        row = {k: v.strip() for k, v in row.items()}
        _date(row["date"], where)
        if row["date"] < last:
            raise RegistryError(f"{where}: rows must be in date order")
        last = row["date"]
        if not row["organisation_system"] or not row["what_happened"]:
            raise RegistryError(f"{where}: organisation_system and what_happened are required")
        if row["type"] not in TYPES:
            raise RegistryError(f"{where}: type {row['type']!r} is not one of {sorted(TYPES)}")
        if row["ai_link"] not in ROLES:
            raise RegistryError(f"{where}: ai_link {row['ai_link']!r} is not one of {sorted(ROLES)}")
        if (row["type"] == "milestone") != (row["ai_link"] == "milestone"):
            raise RegistryError(f"{where}: a milestone has type and ai_link both 'milestone'")
        if row["evidence"] not in EVIDENCE:
            raise RegistryError(f"{where}: evidence {row['evidence']!r} is not one of {sorted(EVIDENCE)}")
        _url(row["source_url"], where, True)
        _url(row["second_source_url"], where, False)
        for key, value in row.items():
            if any(d in value for d in DASHES):
                raise RegistryError(f"{where}: {key} holds a long dash; use a hyphen")
        key = (row["date"], row["organisation_system"])
        if key in seen:
            raise RegistryError(f"{where}: {key} appears twice")
        seen.add(key)
        rows.append(row)
    if not rows:
        raise RegistryError("the registry has no rows")
    return rows


def load_meta(text):
    meta = json.loads(text)
    version, as_of = str(meta.get("data_version", "")), str(meta.get("as_of", ""))
    if len(version) != 8 or not version.isdigit():
        raise RegistryError("meta.json: data_version must be eight digits, YYYYMMDD")
    _date(as_of, "meta.json", full=True)
    if version != as_of.replace("-", ""):
        raise RegistryError("meta.json: data_version must be the as_of date")
    return {"data_version": version, "as_of": as_of}


def build_payload(rows, meta):
    cases = [r for r in rows if r["ai_link"] != "milestone"]
    by_role = {k: sum(1 for r in cases if r["ai_link"] == k) for k in ROLES if k != "milestone"}
    return {
        "schema": "incident-registry/v1",
        "data_version": meta["data_version"],
        "as_of": meta["as_of"],
        "source": "https://github.com/armanobosyan/incident-registry",
        "licence": "CC BY 4.0",
        "counts": {"cases": len(cases), "milestones": len(rows) - len(cases), "by_role": by_role},
        "roles": ROLES,
        "types": TYPES,
        "columns": COLUMNS,
        "rows": rows,
    }


def render(payload):
    return json.dumps(payload, ensure_ascii=False, indent=1) + "\n"


def main(argv):
    check = argv[1:] == ["--check"]
    if argv[1:] and not check:
        print(__doc__)
        return 2
    try:
        rows = load_rows(CSV_PATH.read_text(encoding="utf-8"))
        meta = load_meta(META_PATH.read_text(encoding="utf-8"))
    except RegistryError as e:
        print(f"FAIL: {e}")
        return 1
    text = render(build_payload(rows, meta))
    if check:
        current = OUT_PATH.read_text(encoding="utf-8") if OUT_PATH.exists() else ""
        if current != text:
            print("FAIL: public/registry.v1.json is stale; run python tools/build.py")
            return 1
        print(f"ok: {len(rows)} rows, payload current")
        return 0
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT_PATH.relative_to(ROOT)}: {len(rows)} rows, data_version {meta['data_version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
