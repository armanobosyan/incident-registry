"""Count NVD CVE records by publication date for each year from 2008 (NVD API 2.0).

Rejected records are included, as the API includes them unless noRejected is set.
Each year is asked for in quarters (the API's date window is at most 120 days), and
without an API key NVD allows 5 requests per 30 seconds, so the script waits 6.5 s
between requests. The last day counted is the day before UNTIL.

    python cve/count_nvd.py <out.json> [UNTIL as YYYY-MM-DD, default today]
"""
import datetime
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "Mozilla/5.0 (compatible; research-script)"


def windows(year, until):
    for m1, m2, d2 in ((1, 3, 31), (4, 6, 30), (7, 9, 30), (10, 12, 31)):
        a, b = datetime.date(year, m1, 1), datetime.date(year, m2, d2)
        if a >= until:
            continue
        yield a, min(b, until - datetime.timedelta(days=1))


def count(a, b):
    url = (f"{BASE}?pubStartDate={a.isoformat()}T00:00:00.000Z"
           f"&pubEndDate={b.isoformat()}T23:59:59.999Z&resultsPerPage=1")
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)["totalResults"]
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            print(f"  retry {attempt + 1} {a}..{b}: {e}", flush=True)
            time.sleep(15 + attempt * 10)
    raise SystemExit(f"FAILED {a}..{b}")


def main(out_path, until=None):
    until = datetime.date.fromisoformat(until) if until else datetime.date.today()
    res = {}
    for year in range(2008, until.year + 1):
        parts = []
        for a, b in windows(year, until):
            parts.append([a.isoformat(), b.isoformat(), count(a, b)])
            time.sleep(6.5)
        res[str(year)] = {"total": sum(p[2] for p in parts), "parts": parts, "through": parts[-1][1]}
        print(year, res[str(year)]["total"], flush=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)


if __name__ == "__main__":
    main(*sys.argv[1:3])
