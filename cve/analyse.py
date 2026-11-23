"""The CVE numbers in the article, from the extracted CVE.org table, CISA KEV and NVD.

1. The jump by issuer (CNA): records in state PUBLISHED with datePublished from 1 January
   to WINDOW_END, this year against last year.
2. Finder credits that mention AI, same windows, in two groups: the credit names an AI
   model or tool; or it names only an AI company (or someone at one) and does not say a
   model did the work.
3. Per publication-year cohort: how many records CISA added to KEV within 180 days of
   publication, per 1,000 published.
4. Per year: CVE.org published and rejected records next to the NVD count.

    python cve/analyse.py <cve.jsonl> <kev.json> <nvd.json> [YEAR WINDOW_END SNAPSHOT]
    defaults: 2026 11-16 2026-11-17

kev.json is CISA's known_exploited_vulnerabilities.json; nvd.json is count_nvd.py's output.
"""
import collections
import datetime
import json
import re
import sys

TOOL = re.compile(r"(big ?sleep|\bclaude\b|aardvark|\bcodex\b|chatgpt|\bgpt[- ]?\d|\bgemini\b|codemender|"
                  r"\bllms?\b|large language model|\bai[- ]agents?\b|\bai sast\b|\bo3\b)", re.I)
ORG = re.compile(r"(anthropic|openai|\bxbow\b|zeropath|\baisle\b|depthfirst)", re.I)


def main(cve_path, kev_path, nvd_path, year="2026", window_end="11-16", snapshot="2026-11-17"):
    year = int(year)
    rows = [json.loads(line) for line in open(cve_path, encoding="utf-8")]
    published = [r for r in rows if r["state"] == "PUBLISHED"]

    def in_window(pub, y):
        return f"{y}-01-01" <= pub <= f"{y}-{window_end}"

    # 1. by issuer
    by = {y: collections.Counter(r["assigner"] for r in published if in_window(r["pub"], y))
          for y in (year - 1, year)}
    before, after = sum(by[year - 1].values()), sum(by[year].values())
    growth = after - before
    print(f"1. published 1 Jan - {window_end}: {year - 1} {before:,}, {year} {after:,}, growth {growth:,}")
    issuers = set(by[year - 1]) | set(by[year])
    delta = sorted(((by[year][a] - by[year - 1][a], a) for a in issuers), reverse=True)
    for d, a in delta[:6]:
        print(f"   {a:24s} {by[year - 1][a]:7,} -> {by[year][a]:7,}  +{d:,}  {100 * d / growth:.1f}%")
    top4 = sum(d for d, _ in delta[:4])
    rest = delta[6:]
    print(f"   top four: {top4:,} = {100 * top4 / growth:.1f}% of the growth")
    print(f"   the other {len(rest)} issuers: {sum(d for d, _ in rest):+,}, {sum(1 for d, _ in rest if d > 0)} of them grew")
    new = [a for a in issuers if by[year - 1][a] == 0]
    print(f"   issuers with nothing last year: {sum(by[year][a] for a in new):,} records")
    both = [a for a in issuers if by[year - 1][a] and by[year][a]]
    b0, b1 = sum(by[year - 1][a] for a in both), sum(by[year][a] for a in both)
    print(f"   issuers in both windows: x{b1 / b0:.2f}")

    # 2. AI in finder credits
    print("2. finder credits")
    ai = {}
    for y in (year - 1, year):
        tool = org = 0
        for r in published:
            if not in_window(r["pub"], y):
                continue
            text = " | ".join(v for _, v in r["credits"])
            if TOOL.search(text):
                tool += 1
            elif ORG.search(text):
                org += 1
        ai[y] = (tool, org)
        print(f"   {y}: names a model or tool {tool:,}; names only an AI company {org:,}")
    dt = ai[year][0] - ai[year - 1][0]
    do = ai[year][1] - ai[year - 1][1]
    print(f"   growth: tool {dt:+,} ({100 * dt / growth:.2f}%), company only {do:+,}, "
          f"together {dt + do:+,} ({100 * (dt + do) / growth:.2f}%)")

    # 3. KEV within 180 days
    print("3. added to KEV within 180 days, per 1,000 published")
    kev = json.load(open(kev_path, encoding="utf-8"))["vulnerabilities"]
    pub = {r["id"]: r["pub"] for r in rows}
    snap = datetime.date.fromisoformat(snapshot)
    cohorts = {str(y): (f"{y}-01-01", f"{y}-12-31") for y in range(2022, year)}
    cohorts[f"{year} Q1"] = (f"{year}-01-01", f"{year}-03-31")
    for name, (a, b) in cohorts.items():
        den = sum(1 for r in published if a <= r["pub"] <= b)
        num = 0
        for v in kev:
            p = pub.get(v["cveID"])
            if p and a <= p <= b:
                days = (datetime.date.fromisoformat(v["dateAdded"]) - datetime.date.fromisoformat(p)).days
                num += days <= 180
        full = datetime.date.fromisoformat(b) + datetime.timedelta(days=180) <= snap
        print(f"   {name:8s} {num:4d} of {den:6,} = {1000 * num / den:.1f}"
              + ("" if full else "  (180 days not yet over)"))

    # 4. CVE.org against NVD, per year
    print("4. per year: CVE.org published / rejected, NVD")
    nvd = {k: v["total"] for k, v in json.load(open(nvd_path, encoding="utf-8")).items()}
    per = collections.defaultdict(collections.Counter)
    for r in rows:
        per[r["pub"][:4]][r["state"]] += 1
    for y in sorted(per):
        c = per[y]
        n = nvd.get(y)
        gap = f"  NVD {100 * (n / c['PUBLISHED'] - 1):+.1f}%" if n else ""
        print(f"   {y}: {c['PUBLISHED']:7,} / {c['REJECTED']:5,}   NVD {n or '-':>7}{gap}")


if __name__ == "__main__":
    main(*sys.argv[1:])
