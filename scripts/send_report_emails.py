#!/usr/bin/env python3
"""Prepare or send one report email per row in emails.csv."""

from __future__ import annotations

import argparse
import html
import os
import re
import smtplib
import ssl
import sys
from dataclasses import dataclass
from datetime import date
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formataddr, formatdate
from pathlib import Path
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parent
CSV_FIELDS = ("url", "email", "pdf_path")
REPORT_DATE = re.compile(r"--(\d{4}-\d{2}-\d{2})--")
POLISH_MONTHS = (
    "stycznia", "lutego", "marca", "kwietnia", "maja", "czerwca",
    "lipca", "sierpnia", "września", "października", "listopada", "grudnia",
)
COMPANY = "Codefellow Sp. z o.o."
CONTACT_EMAIL = "kontakt@codefellow.pl"
CONTACT_PHONE = "+48 795 309 804"
WEBSITE = "https://codefellow.pl/"
DISPLAY_NAME = "Stronoskop · Codefellow Sp. z o.o."
SMTP_ENV_KEYS = frozenset(
    ("SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM")
)


@dataclass(frozen=True)
class ReportEmail:
    recipient: str
    domain: str
    report_date: date
    pdf_path: Path


def normalize_host(host: str) -> str:
    value = host.casefold().rstrip(".")
    return value[4:] if value.startswith("www.") else value


def polish_date(value: date) -> str:
    return f"{value.day} {POLISH_MONTHS[value.month - 1]} {value.year}"


def validated_address(value: str, label: str) -> str:
    if not value or value != value.strip() or any(char.isspace() for char in value):
        raise ValueError(f"Nieprawidłowy adres {label}: {value!r}")
    try:
        parsed = Address(addr_spec=value)
    except ValueError as error:
        raise ValueError(f"Nieprawidłowy adres {label}: {value!r}") from error
    if parsed.addr_spec != value:
        raise ValueError(f"Nieprawidłowy adres {label}: {value!r}")
    return value


def load_emails(csv_path: Path) -> list[ReportEmail]:
    import csv

    records: list[ReportEmail] = []
    root = PROJECT_ROOT.resolve()
    with csv_path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source, delimiter=";")
        if reader.fieldnames is None or any(name not in reader.fieldnames for name in CSV_FIELDS):
            raise ValueError("CSV musi zawierać kolumny: url;email;pdf_path")

        for line_number, row in enumerate(reader, start=2):
            if None in row:
                raise ValueError(f"Wiersz {line_number}: nieoczekiwane dodatkowe kolumny")
            values = {name: (row.get(name) or "").strip() for name in CSV_FIELDS}
            if not all(values.values()):
                raise ValueError(f"Wiersz {line_number}: url, email i pdf_path są wymagane")

            try:
                parsed_url = urlsplit(values["url"])
                if (
                    parsed_url.scheme.casefold() not in ("http", "https")
                    or not parsed_url.hostname
                    or parsed_url.username
                    or parsed_url.password
                ):
                    raise ValueError("URL musi wskazywać publiczną stronę HTTP(S)")
                domain = parsed_url.hostname.encode("idna").decode("ascii").casefold().rstrip(".")
                recipient = validated_address(values["email"], "e-mail")
                raw_pdf_path = Path(values["pdf_path"])
                pdf_path = (raw_pdf_path if raw_pdf_path.is_absolute() else root / raw_pdf_path).resolve()
                if root not in pdf_path.parents:
                    raise ValueError("ścieżka załącznika wychodzi poza katalog projektu")
                if pdf_path.suffix.casefold() != ".pdf" or not pdf_path.is_file():
                    raise ValueError(f"brak pliku PDF: {values['pdf_path']}")
                with pdf_path.open("rb") as pdf_file:
                    if pdf_file.read(5) != b"%PDF-":
                        raise ValueError(f"załącznik nie wygląda na PDF: {values['pdf_path']}")

                date_match = REPORT_DATE.search(pdf_path.stem)
                if date_match is None:
                    raise ValueError(f"brak daty analizy w nazwie PDF: {pdf_path.name}")
                report_date = date.fromisoformat(date_match.group(1))
                report_domain = pdf_path.stem.split("--", 1)[0]
                if normalize_host(domain) != normalize_host(report_domain):
                    raise ValueError(
                        f"domena URL ({domain}) nie zgadza się z raportem ({report_domain})"
                    )
            except (UnicodeError, ValueError) as error:
                raise ValueError(f"Wiersz {line_number}: {error}") from error

            records.append(ReportEmail(recipient, domain, report_date, pdf_path))

    if not records:
        raise ValueError("CSV nie zawiera żadnych wiadomości do przygotowania")
    return records


def message_paragraphs(record: ReportEmail) -> tuple[str, ...]:
    return (
        "Szanowni Państwo,",
        f"przesyłamy raport dotyczący strony {record.domain} z prośbą o przekazanie go "
        "administratorowi lub firmie odpowiedzialnej za utrzymanie serwisu.",
        "Raport przygotował zespół Codefellow. Zajmujemy się m.in. audytami "
        "bezpieczeństwa stron internetowych. "
        f"{polish_date(record.report_date)} r. za pomocą narzędzia Stronoskop "
        "przeprowadziliśmy automatyczną, pasywną analizę publicznie dostępnej "
        "części serwisu. W załączonym raporcie opisaliśmy zakres analizy i "
        "wskazaliśmy elementy konfiguracji, które warto zweryfikować. Ich "
        "znaczenie najlepiej oceni administrator znający konfigurację strony. "
        "Analiza nie obejmowała logowania ani prób wykorzystania podatności.",
        "W razie pytań dotyczących raportu mogą Państwo odpowiedzieć bezpośrednio "
        "na tę wiadomość.",
    )


def message_text(record: ReportEmail) -> str:
    signature = (
        "Z poważaniem,\n"
        "Zespół Stronoskop\n"
        f"{COMPANY}\n"
        f"{CONTACT_EMAIL} · {CONTACT_PHONE}\n"
        f"{WEBSITE}"
    )
    return "\n\n".join((*message_paragraphs(record), signature))


def message_html(record: ReportEmail) -> str:
    body = "\n      ".join(
        f"<p>{html.escape(paragraph)}</p>" for paragraph in message_paragraphs(record)
    )
    return f"""<!doctype html>
<html lang="pl">
  <body style="margin:0;padding:24px;font-family:Arial,Helvetica,sans-serif;line-height:1.6;color:#252a31">
    <div style="max-width:640px;margin:0 auto">
      {body}
      <p style="margin-top:28px">Z poważaniem,<br><strong>Zespół Stronoskop</strong><br>{html.escape(COMPANY)}<br><a href="mailto:{html.escape(CONTACT_EMAIL, quote=True)}">{html.escape(CONTACT_EMAIL)}</a> · {html.escape(CONTACT_PHONE)}<br><a href="{html.escape(WEBSITE, quote=True)}">codefellow.pl</a></p>
    </div>
  </body>
</html>"""

def build_message(record: ReportEmail, from_address: str) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = f"{record.domain} – raport techniczny dla administratora strony"
    message["From"] = formataddr((DISPLAY_NAME, from_address))
    message["To"] = record.recipient
    message["Reply-To"] = CONTACT_EMAIL
    message["Date"] = formatdate(localtime=True)
    message.set_content(message_text(record))
    message.add_alternative(message_html(record), subtype="html")
    message.add_attachment(
        record.pdf_path.read_bytes(),
        maintype="application",
        subtype="pdf",
        filename=record.pdf_path.name,
    )
    return message


def load_smtp_env_file() -> None:
    """Load SMTP settings from the project .env without executing it."""
    env_path = PROJECT_ROOT / ".env"
    try:
        lines = env_path.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        return

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or key not in SMTP_ENV_KEYS:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ.setdefault(key, value)


def smtp_settings() -> tuple[str, int, str, str, str]:
    host = os.environ.get("SMTP_HOST", "").strip()
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    from_address = os.environ.get("SMTP_FROM", "").strip()
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
    except ValueError as error:
        raise ValueError("SMTP_PORT musi być liczbą") from error
    if not host or not username or not password or not from_address:
        raise ValueError(
            "W trybie wysyłki ustaw SMTP_HOST, SMTP_PORT, SMTP_USERNAME, "
            "SMTP_PASSWORD i SMTP_FROM w pliku .env lub zmiennych środowiskowych"
        )
    if not 1 <= port <= 65535:
        raise ValueError("SMTP_PORT musi być w zakresie 1–65535")
    validated_address(from_address, "nadawcy SMTP_FROM")
    return host, port, username, password, from_address


def send_emails(records: list[ReportEmail], settings: tuple[str, int, str, str, str]) -> None:
    host, port, username, password, from_address = settings
    context = ssl.create_default_context()
    if port == 465:
        smtp = smtplib.SMTP_SSL(host, port, timeout=30, context=context)
    else:
        smtp = smtplib.SMTP(host, port, timeout=30)

    sent = 0
    with smtp:
        if port != 465:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
        smtp.login(username, password)
        for record in records:
            message = build_message(record, from_address)
            refused = smtp.send_message(message)
            if refused:
                raise smtplib.SMTPRecipientsRefused(refused)
            sent += 1
            print(f"Wysłano {sent}/{len(records)}: {record.recipient} — {record.domain}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Przygotuj lub wyślij raporty PDF z emails.csv; domyślnie tylko podgląd."
    )
    parser.add_argument(
        "--csv", type=Path, default=PROJECT_ROOT / "emails.csv",
        help="Plik CSV url;email;pdf_path (domyślnie emails.csv).",
    )
    parser.add_argument(
        "--send", action="store_true",
        help="Wyślij indywidualną wiadomość do każdego adresu z CSV.",
    )
    args = parser.parse_args()

    try:
        load_smtp_env_file()
        records = load_emails(args.csv)
        if args.send:
            send_emails(records, smtp_settings())
        else:
            print(f"Podgląd: przygotowano {len(records)} indywidualnych wiadomości; nic nie wysłano.")
            preview_from = os.environ.get("SMTP_FROM", CONTACT_EMAIL).strip()
            validated_address(preview_from, "nadawcy SMTP_FROM")
            for index, record in enumerate(records, start=1):
                message = build_message(record, preview_from)
                attachments = list(message.iter_attachments())
                if (
                    len(attachments) != 1
                    or attachments[0].get_filename() != record.pdf_path.name
                    or attachments[0].get_content_type() != "application/pdf"
                ):
                    raise ValueError(f"Nieprawidłowy załącznik dla {record.domain}")
                print(
                    f"{index}. Do: {record.recipient} | Temat: {message['Subject']} "
                    f"| PDF: {record.pdf_path.name}"
                )
            print("Wysyłka wymaga SMTP_* w .env lub środowisku oraz jawnej opcji --send.")
    except (OSError, ValueError, smtplib.SMTPException) as error:
        print(f"Błąd: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
