from pathlib import Path
import csv

BASE_DIR = Path(__file__).resolve().parent
SOURCE_DIR = BASE_DIR / "output" / "pdf-hr"
OUTPUT_FILE = BASE_DIR / "input" / "hr.csv"

urls = set()

for file in SOURCE_DIR.glob("*.pdf"):
    domain = file.name.split("--", 1)[0]
    urls.add(f"https://{domain}")

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["url"])

    for url in sorted(urls):
        writer.writerow([url])

print(f"Zapisano {len(urls)} adresów do {OUTPUT_FILE}")