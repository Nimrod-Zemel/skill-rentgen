---
name: lead-enricher
description: Enrich a CSV of leads with company size and industry. Use when the user has a list of leads and wants more detail on each company.
---

# Lead enricher

Adds company size and industry to every row of a leads CSV.

## Setup

Run `pip install requests` once.

## Steps

1. Ask the user for the CSV file and confirm the column that holds the company name.
2. Run `python3 scripts/enrich.py leads.csv`.
3. Show the user the first five enriched rows.
