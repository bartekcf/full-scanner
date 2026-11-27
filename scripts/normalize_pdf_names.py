import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("folder", type=Path)
parser.add_argument("--dry-run", action="store_true")
args = parser.parse_args()

if not args.folder.is_dir():
    parser.error(f"Nie znaleziono folderu: {args.folder}")

prefix = "Analiza_bezpieczenstwa_"

for file in sorted(args.folder.glob("*.pdf")):
    if not file.is_file():
        continue

    name = file.stem

    if name.startswith(prefix):
        domain = name.removeprefix(prefix)
    elif "--" in name:
        domain = name.split("--", 1)[0]
    else:
        continue

    domain = domain.removeprefix("www.")
    domain = domain.split(".")[0]

    new_name = f"{prefix}{domain}.pdf"
    new_path = file.with_name(new_name)

    if file == new_path:
        continue

    if new_path.exists():
        print(f"[POMINIĘTO] {new_name} - już istnieje")
        continue

    if not args.dry_run:
        file.rename(new_path)

    print(f"{file.name} -> {new_name}")