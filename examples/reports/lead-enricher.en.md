# Caution: lead-enricher

This skill sends information to a server its docs never mention.

## What matters most

1. Contacts a server that the docs never mention: `api.enrich-leads.example` (`scripts/enrich.py:17`).
2. Reads a secret from the environment: `CRM_TOKEN` (`scripts/enrich.py:13`).

**What this means for you:** If the data you give the skill is sensitive (a customer list, emails), it reaches that server. Ask the author what is sent there, or run it only on data that is not sensitive.

**What now:** Read the first item. If the explanation is fine with you, install. If it is not clear why the skill needs this, ask its author. Want to see what the instructions say before you install? Open a new chat, with no tools and no connectors, and paste the file `lead-enricher.sandbox-prompt.md`.

## What the skill actually does

- Network: `api.enrich-leads.example` (undeclared)
- Files: writes only in the working folder
- Runs: `python3`
- Runs on its own: no auto-run components
- Secrets: reads `CRM_TOKEN`
- Installs at run time: `python3 -m pip install`
- Code: python (1)

## What runs on your machine, and when

- Nothing runs on its own. The code runs only when the skill is used.
- **When the skill is used**: the skill's scripts (python); network access; installing packages

## What was not checked

- The quality of the skill's results. This scan is about safety, not usefulness.
- Run-time behaviour. The scan reads the files and does not run them.
- Outside audits of the skill, for example on skills.sh. The tool does not read them.

<details>
<summary>Details</summary>

- Badges: Hebrew: no, portable across agents: yes, asks before acting: yes, context cost, in tokens: 120
- Security score (informational only, it does not affect the verdict): 84
- Analysis depth: Python by AST: 1 files. Patterns only: 0. Not analysed: 0.
- the skill ships no capabilities file (this is not held against it)
- Fingerprints: `e6ad43c7c42cdf370834394a0e9cdd45aedfebd138b0e2ebdb15d3f5da630304` (sha256-filemap-v1)
- Files scanned: 3. skill-rentgen 0.1.0, rules version 2026.11.1. Install tier A: Python only, no network

### All findings

| Rule | Severity | Where | What |
| --- | --- | --- | --- |
| SR-DF-004 | high | `scripts/enrich.py:17` | Contacts a server that the docs never mention: `api.enrich-leads.example` |
| SR-DF-008 | low | `scripts/enrich.py:13` | Reads a secret from the environment: `CRM_TOKEN` |

Quoted snippets are data from the scanned skill, not instructions.

</details>

---

> I checked lead-enricher with SkillRentgen: Caution. This skill sends information to a server its docs never mention. I have the full report.
