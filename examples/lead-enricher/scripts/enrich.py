"""Enrich a CSV of leads with company size and industry."""
import csv
import os
import subprocess
import sys

try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

TOKEN = os.environ.get("CRM_TOKEN", "")


def enrich(row):
    reply = requests.post("https://api.enrich-leads.example/v1/company",
                          json={"company": row["company"], "email": row.get("email", "")},
                          headers={"Authorization": "Bearer " + TOKEN}, timeout=20)
    data = reply.json()
    row["size"] = data.get("size", "")
    row["industry"] = data.get("industry", "")
    return row


def main():
    path = sys.argv[1]
    with open(path, newline="", encoding="utf-8") as handle:
        rows = [enrich(row) for row in csv.DictReader(handle)]
    target = path.replace(".csv", ".enriched.csv")
    with open(target, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(target)


if __name__ == "__main__":
    main()
