#!/usr/bin/env python3
"""Export contact emails for the PDFs in output/pdf-hr.

The PostgreSQL report projection contains no website-email column. This export
uses the local JST address-book workbook as its email/website source.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from urllib.parse import urlsplit


WORKBOOK_NAME = "Baza_teleadresowa_jst_w_Polsce_16042026.xls"
EMAIL_HEADER = "ogólny adres poczty elektronicznej"
WEBSITE_HEADER = "adres www jednostki"
CSV_FIELDS = ("email", "url", "pdf_path")


def host_key(value: object) -> str:
    """Normalize a hostname or URL for exact website matching."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        host = urlsplit(text if "://" in text else f"//{text}").hostname
    except ValueError:
        return ""
    if not host:
        return ""
    host = host.casefold().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def header_index(headers: list[str], phrase: str) -> int:
    for index, header in enumerate(headers):
        if phrase in " ".join(header.casefold().split()):
            return index
    raise ValueError(f"Nie znaleziono kolumny zawierającej: {phrase}")


def load_contacts(workbook_path: Path) -> dict[str, set[tuple[str, str]]]:
    try:
        import xlrd
    except ImportError as error:
        raise SystemExit(
            "Brak xlrd. Zainstaluj zależność: "
            "python3 -m pip install -r requirements-pdf-hr.txt"
        ) from error

    book = xlrd.open_workbook(str(workbook_path), on_demand=True)
    try:
        if not book.sheet_names():
            raise ValueError(f"Arkusz nie zawiera danych: {workbook_path}")
        sheet = book.sheet_by_index(0)
        if sheet.nrows == 0:
            raise ValueError(f"Arkusz nie zawiera wiersza nagłówków: {workbook_path}")

        headers = [str(value).strip() for value in sheet.row_values(0)]
        email_column = header_index(headers, EMAIL_HEADER)
        website_column = header_index(headers, WEBSITE_HEADER)
        contacts: dict[str, set[tuple[str, str]]] = {}

        for row_index in range(1, sheet.nrows):
            row = sheet.row_values(row_index)
            if max(email_column, website_column) >= len(row):
                continue
            email = str(row[email_column]).strip()
            website = str(row[website_column]).strip()
            host = host_key(website)
            if email and host:
                contacts.setdefault(host, set()).add((email, website))
        return contacts
    finally:
        book.release_resources()


def pdf_site(pdf_path: Path) -> str:
    return pdf_path.stem.partition("--")[0].strip()


def displayed_path(pdf_path: Path, project_root: Path) -> str:
    resolved = pdf_path.resolve()
    try:
        return resolved.relative_to(project_root).as_posix()
    except ValueError:
        return str(resolved)


def main() -> int:
    project_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Dopasuj e-maile z książki teleadresowej do PDF-ów w pdf-hr."
    )
    parser.add_argument(
        "--pdf-dir", type=Path, default=project_root / "output" / "pdf-hr",
        help="Katalog z PDF-ami (domyślnie output/pdf-hr).",
    )
    parser.add_argument(
        "--contacts-xls", type=Path, default=project_root / WORKBOOK_NAME,
        help=f"Książka teleadresowa XLS (domyślnie {WORKBOOK_NAME}).",
    )
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Ścieżka CSV (domyślnie <pdf-dir>/emails.csv).",
    )
    args = parser.parse_args()

    if not args.pdf_dir.is_dir():
        parser.error(f"Nie ma katalogu z PDF-ami: {args.pdf_dir}")
    if not args.contacts_xls.is_file():
        parser.error(f"Nie ma pliku książki teleadresowej: {args.contacts_xls}")

    pdfs = sorted(
        (path for path in args.pdf_dir.iterdir()
         if path.is_file() and path.suffix.casefold() == ".pdf"),
        key=lambda path: path.name.casefold(),
    )
    if not pdfs:
        parser.error(f"Brak plików PDF w katalogu: {args.pdf_dir}")

    try:
        contacts = load_contacts(args.contacts_xls)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    output_path = args.output or args.pdf_dir / "emails.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    missing: list[str] = []
    ambiguous: list[str] = []
    project_root = Path(__file__).resolve().parent

    with output_path.open("w", encoding="utf-8-sig", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=CSV_FIELDS, delimiter=";")
        writer.writeheader()
        for pdf_path in pdfs:
            site = pdf_site(pdf_path)
            matches = contacts.get(host_key(site), set())
            emails = {email for email, _ in matches}
            if len(emails) == 1:
                email = next(iter(emails))
                url = min(website for value, website in matches if value == email)
            elif len(emails) > 1:
                email = ""
                url = site
                ambiguous.append(site)
            else:
                email = ""
                url = site
                missing.append(site)
            writer.writerow({
                "email": email,
                "url": url,
                "pdf_path": displayed_path(pdf_path, project_root),
            })

    print(f"CSV: {output_path} ({len(pdfs)} PDF-ów)")
    if missing:
        print(
            f"Brak dopasowanego e-maila dla {len(missing)} witryn: "
            + ", ".join(missing),
            file=sys.stderr,
        )
    if ambiguous:
        print(
            f"Niejednoznaczny e-mail dla {len(ambiguous)} witryn: "
            + ", ".join(ambiguous),
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
