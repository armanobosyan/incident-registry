"""Extract a compact table from a CVE.org cvelistV5 snapshot.

Reads the snapshot zip published in the cvelistV5 releases (the outer zip that holds
cves.zip) without unpacking it to disk, keeps every record with datePublished from
2021-01-01, and writes one JSON line per record:
    id, state, pub (YYYY-MM-DD), assigner, credits (list of [type, value])

    python cve/extract_cvelist.py <snapshot.zip> <out.jsonl>
"""
import io
import json
import sys
import zipfile

FROM = "2021-01-01"


def main(outer_path, out_path):
    n_all = n_kept = 0
    with zipfile.ZipFile(outer_path) as outer:
        inner_name = [n for n in outer.namelist() if n.endswith(".zip")][0]
        with zipfile.ZipFile(io.BytesIO(outer.read(inner_name))) as inner, \
                open(out_path, "w", encoding="utf-8") as out:
            for name in inner.namelist():
                if not (name.endswith(".json") and "/CVE-" in name):
                    continue
                n_all += 1
                try:
                    rec = json.loads(inner.read(name))
                except ValueError:
                    continue
                meta = rec.get("cveMetadata", {})
                pub = (meta.get("datePublished") or "")[:10]
                if pub < FROM:
                    continue
                cna = rec.get("containers", {}).get("cna", {})
                credits = [[c.get("type", ""), c.get("value", "")]
                           for c in cna.get("credits", []) if isinstance(c, dict)]
                out.write(json.dumps({
                    "id": meta.get("cveId"), "state": meta.get("state"), "pub": pub,
                    "assigner": meta.get("assignerShortName") or meta.get("assignerOrgId"),
                    "credits": credits,
                }) + "\n")
                n_kept += 1
    print(f"read {n_all} records, kept {n_kept} published from {FROM}")


if __name__ == "__main__":
    main(*sys.argv[1:3])
