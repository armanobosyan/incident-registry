# Incident registry

Large failures of computer systems since 1995, and what AI had to do with each one: outages, breaches, attacks, supply-chain compromises and vulnerabilities, with ten milestones for context.

It is the data behind the article [The bigger the system, the harder it falls](https://sugra.systems/blog/how-big-systems-fail). The article's appendix is built from `public/registry.v1.json` in this repository every time the blog is built, so a case added here appears there with the next build.

## What is here

| Path | What it is |
|---|---|
| `data/registry.csv` | One row per case, in date order |
| `data/meta.json` | `data_version` and `as_of` of the current data |
| `public/registry.v1.json` | The two above, checked and built into one file the blog reads |
| `tools/build.py` | Checks the CSV and writes the JSON |
| `tests/` | Tests for the checks and for the committed data |
| `cve/` | The scripts behind the article's CVE numbers |

## Columns

| Column | What it holds |
|---|---|
| `date` | `YYYY-MM-DD`; `YYYY-MM` or `YYYY` when the sources give only the month or the year |
| `organisation_system` | Who or what failed |
| `type` | `outage`, `breach`, `attack`, `supply_chain`, `vulnerability`, `research` or `milestone` |
| `what_happened` | One or two sentences |
| `impact` | Scale, as the sources state it |
| `cause` | The cause, as the sources state it |
| `ai_link` | What AI had to do with it, below |
| `evidence` | `confirmed` (the organisation or an official record states it) or `reported` (press or researchers only) |
| `source_url` | The main source |
| `second_source_url` | A second source, when there is one |

| `ai_link` | Shown as | Meaning |
|---|---|---|
| `none` | Not AI | No source names AI in the cause, the attack or the find |
| `ai_direct` | AI the cause | An AI system did the damage, carried the attack or held the flaw, or AI output was the problem, as with fabricated bug reports |
| `ai_around` | AI around it | AI was close by: an AI vendor, an AI feature, AI crawler traffic or AI as the target. The sources name another cause |
| `ai_found` | AI found it | An AI system found the flaw |
| `milestone` | Milestone | Not a failure: a date for context, such as a product launch |

## Adding or changing a case

1. Edit `data/registry.csv`. Keep the date order, use a hyphen rather than a long dash, and give an `https` source.
2. Set `data/meta.json`: `as_of` to the day of the change and `data_version` to the same date as eight digits, for example `20261122`.
3. Run `python tools/build.py`, then `python -m unittest discover -s tests`.
4. Commit the CSV, `meta.json` and `public/registry.v1.json` together. `python tools/build.py --check` fails while the JSON is out of date.

Python 3, standard library only.

A missing case or a mistake: open an issue with a link to the source.

## The CVE numbers

The scripts in `cve/` produce the vulnerability figures in the article:

1. `extract_cvelist.py` reads a [CVE.org cvelistV5](https://github.com/CVEProject/cvelistV5) snapshot zip and keeps a compact table of records published from 2021.
2. `count_nvd.py` counts NVD records per year from 2008 through the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities).
3. `analyse.py` takes that table, the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and the NVD counts, and prints the growth by issuing organisation, the finder credits that mention AI, the share of each year's records added to KEV within 180 days, and CVE.org next to NVD per year.

## Licence

Code: MIT, see `LICENSE`. Data (`data/` and `public/`): [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), see `LICENSE-DATA`. Credit "Incident registry" with a link to this repository.
