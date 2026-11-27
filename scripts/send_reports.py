#!/usr/bin/env python3
"""Send individually addressed security reports after a local preflight.
Python 3.10+; requires Poppler pdftotext and python-dotenv.
"""
import argparse
import csv
import hashlib
from html import escape
import os
import re
import shutil
import smtplib
import sqlite3
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from getpass import getpass
from pathlib import Path

HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]{2,63}")
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SIGNATURE = "Bartłomiej Kędziora\nSoftware Developer | Web Security\nCodefellow Sp. z o.o.\nscout@codefellow.pl\n+48 795 309 804 | codefellow.pl"

def load_environment():
    try:
        from dotenv import load_dotenv
    except ImportError:
        if (ROOT / ".env").exists():
            raise ValueError("Zainstaluj python-dotenv: python3 -m pip install python-dotenv")
    else:
        load_dotenv(ROOT / ".env", override=False)


def load_html_signature(path, logo_path):
    source = path.read_text(encoding="utf-8")
    match = re.search(r"<body\b[^>]*>(.*?)</body\s*>", source, re.I | re.S)
    fragment = match.group(1).strip() if match else source.strip()
    if 'src="codefellow-logo.png"' not in fragment:
        raise ValueError("Stopka HTML musi zawierać src=\"codefellow-logo.png\"")
    logo = logo_path.read_bytes()
    if not logo.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Logo nie jest plikiem PNG")
    return fragment, logo

@dataclass(frozen=True)
class Report:
    domain: str
    email: str
    path: Path
    finding: str


def canonical(domain):
    return domain.lower().removeprefix('www.')


def load_csv(path):
    reports = []
    domains, paths, emails = set(), set(), set()
    with path.open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if not {'domain', 'email', 'path_to_pdf'} <= set(reader.fieldnames or []):
            raise ValueError('CSV musi mieć kolumny domain,email,path_to_pdf')
        for line, row in enumerate(reader, 2):
            if None in row:
                raise ValueError(f'Wiersz {line}: nadmiarowe pola CSV')
            domain = (row.get('domain') or '').strip().lower()
            email = (row.get('email') or '').strip()
            filename = (row.get('path_to_pdf') or '').strip()
            finding = (row.get('finding') or '').strip()
            if not HOST_RE.fullmatch(domain) or not EMAIL_RE.fullmatch(email) or not filename:
                raise ValueError(f'Wiersz {line}: niepoprawne lub puste dane')
            p = Path(filename).expanduser()
            p = (p if p.is_absolute() else ROOT / p).resolve()
            key = canonical(domain)
            if key in domains or p in paths or email.lower() in emails:
                raise ValueError(f'Wiersz {line}: duplikat domeny, ścieżki lub e-maila; sprawdź ręcznie')
            domains.add(key); paths.add(p); emails.add(email.lower())
            reports.append(Report(domain, email, p, finding))
    if not reports:
        raise ValueError('CSV nie zawiera raportów')
    return reports


def preflight(report, folder):
    if not report.path.is_relative_to(folder) or report.path.suffix.lower() != '.pdf':
        raise ValueError('PDF poza dozwolonym katalogiem lub niewłaściwe rozszerzenie')
    if not report.path.is_file():
        raise ValueError('Brak pliku PDF')
    if report.path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError('PDF przekracza lokalny limit 10 MiB')
    data = report.path.read_bytes()
    if not data.startswith(b'%PDF-'):
        raise ValueError('Nieprawidłowy nagłówek PDF')
    result = subprocess.run(['pdftotext', '-f', '1', '-l', '1', '-enc', 'UTF-8', '-', '-'],
                            input=data, capture_output=True, timeout=30, check=True)
    extracted = result.stdout.decode('utf-8', errors='replace')
    host = re.escape(canonical(report.domain))
    if not re.search(r'(?<![\w.@-])(?:www\.)?' + host + r'(?![\w-]|\.[\w-])', extracted, re.I):
        raise ValueError('Nie znaleziono dokładnej domeny na pierwszej stronie PDF')
    return data


def body(report, signature, generic=False):
    if report.finding:
        observation = f'W przypadku serwisu {report.domain} skan wskazał {report.finding.rstrip(".")}.'
    elif generic:
        observation = f'W przypadku serwisu {report.domain} przygotowaliśmy podsumowanie obserwacji z pasywnego skanowania.'
    else:
        observation = (f'W przypadku serwisu {report.domain} skan wskazał wersję oprogramowania, '
                       'której mogą dotyczyć znane podatności.')
    return ('Dzień dobry,\n\n'
            'w ramach prac nad narzędziem do analizy bezpieczeństwa przeprowadziliśmy '
            'pasywne skanowanie publicznie dostępnych stron polskich urzędów.\n\n'
            f'{observation} Dlatego w załączeniu przesyłam krótki raport z najważniejszymi ustaleniami i zaleceniami. '
            'Proszę o przekazanie go osobie lub firmie odpowiedzialnej za utrzymanie strony.\n\n'
            'W razie pytań dotyczących raportu pozostajemy do Państwa dyspozycji.\n\n'
            f'Z poważaniem\n{signature}\n')


def build_message(report, data, sender, name, signature, test_to=None, generic=False, html_signature=None, logo=None):
    msg = EmailMessage()
    msg['From'] = formataddr((name, sender))
    msg['To'] = test_to or report.email
    msg['Reply-To'] = sender
    msg['Subject'] = ('[TEST] ' if test_to else '') + f'{report.domain} – informacja dla administratora strony'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=sender.split('@')[1])
    msg.set_content(body(report, signature, generic))
    if html_signature is not None:
        logo_cid = make_msgid(domain=sender.split('@')[1])
        fragment = html_signature.replace('src="codefellow-logo.png"', f'src="cid:{logo_cid[1:-1]}"')
        # Escape all message text; the trusted local signature keeps its inline styles.
        message_text = body(report, '', generic).strip()
        paragraphs = ''.join('<p style="margin:0 0 16px 0;">' + escape(part).replace('\n', '<br>') + '</p>'
                             for part in message_text.split('\n\n'))
        html = ('<!doctype html><html lang="pl"><head><meta charset="utf-8"></head>'
                '<body style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;color:#222;">'
                + paragraphs + fragment + '</body></html>')
        msg.add_alternative(html, subtype='html')
        msg.get_payload()[-1].add_related(logo, maintype='image', subtype='png',
                                          cid=logo_cid, disposition='inline', filename='codefellow-logo.png')
    msg.add_attachment(data, maintype='application', subtype='pdf', filename=report.path.name)
    return msg


def open_log(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.execute('''CREATE TABLE IF NOT EXISTS deliveries (
        domain TEXT PRIMARY KEY, email TEXT NOT NULL, pdf_sha256 TEXT NOT NULL,
        message_id TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        error TEXT)''')
    db.commit()
    return db


def main():
    load_environment()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--csv', type=Path, default=ROOT / 'input/urzedy_wysylka_final.csv')
    p.add_argument('--pdf-dir', type=Path, default=ROOT / 'output/urzedy-white-scout')
    p.add_argument('--log', type=Path, default=ROOT / 'output/urzedy_smtp.sqlite3')
    p.add_argument('--signature', type=Path, help='Opcjonalny plik UTF-8 ze stopką tekstową')
    p.add_argument('--signature-html', type=Path, default=ROOT / 'templates/signature.html', help='Stopka HTML')
    p.add_argument('--signature-logo', type=Path, default=ROOT / 'templates/codefellow-logo.png', help='Logo PNG')
    p.add_argument('--domain', help='Wybierz pojedynczą domenę')
    p.add_argument('--limit', type=int, help='Maksymalna liczba wiadomości; domyślnie 1 przy wysyłce')
    p.add_argument('--generic', action='store_true', help='Neutralna treść zamiast wzmianki o wersji oprogramowania')
    p.add_argument('--confirm-version-finding', action='store_true', help='Potwierdź, że wybrane raporty bez finding uzasadniają wzmiankę o wersji oprogramowania')
    p.add_argument('--phone', default='', help='Opcjonalny numer do stopki tekstowej (wyłącza HTML)')
    p.add_argument('--delay', type=float, default=10, help='Przerwa między wiadomościami (sekundy)')
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--send', action='store_true', help='Właściwa wysyłka do adresatów')
    mode.add_argument('--test-to', help='Jedna wiadomość wyłącznie na własny adres testowy')
    args = p.parse_args()
    if (args.limit is not None and args.limit < 1) or args.delay < 0:
        p.error('Niepoprawny limit lub odstęp')
    if args.test_to and not EMAIL_RE.fullmatch(args.test_to):
        p.error('Niepoprawny adres testowy')
    if not shutil.which('pdftotext'):
        p.error('Brak pdftotext: sudo apt install poppler-utils')
    reports = load_csv(args.csv)
    if args.test_to and args.test_to.lower() in {r.email.lower() for r in reports}:
        p.error('Adres testowy nie może należeć do listy adresatów')
    if args.domain:
        reports = [r for r in reports if canonical(r.domain) == canonical(args.domain.strip())]
        if not reports:
            p.error('Nie znaleziono domeny w CSV')
    folder = args.pdf_dir.resolve()
    signature = args.signature.read_text(encoding='utf-8').strip() if args.signature else DEFAULT_SIGNATURE
    html_signature, logo = (None, None) if args.signature or args.phone else load_html_signature(args.signature_html, args.signature_logo)
    if args.phone:
        digits = re.sub(r'[\s()-]', '', args.phone)
        if not re.fullmatch(r'(?:\+48)?[0-9]{9}', digits):
            p.error('Numer telefonu powinien zawierać 9 cyfr, opcjonalnie +48')
        if not args.signature:
            signature = DEFAULT_SIGNATURE.split('\n+48')[0]
        signature += f'\ntel. {args.phone}'
    db = open_log(args.log) if args.send or args.log.exists() else None
    try:
        ready = []
        problems = 0
        for report in reports:
            if not args.test_to and db is not None:
                prev = db.execute('SELECT status FROM deliveries WHERE domain=?', (canonical(report.domain),)).fetchone()
                if prev:
                    print(f'SKIP {report.domain}: w logu {prev[0]}')
                    continue
            try:
                data = preflight(report, folder)
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                print(f'BLOKADA {report.domain}: {exc}')
                problems += 1
                continue
            ready.append((report, data))
            print(f'OK {report.domain} -> {report.email} | {report.path.name}')
        print(f'\nGotowe: {len(ready)}; zablokowane: {problems}; sprawdzane: {len(reports)}')
        if not ready:
            return 1
        if not args.send and not args.test_to:
            print('\n--- PODGLĄD PIERWSZEJ POPRAWNEJ WIADOMOŚCI ---')
            report, _ = ready[0]
            print(f'To: {report.email}\nSubject: {report.domain} – informacja dla administratora strony\n\n{body(report, signature, args.generic)}')
            print('DRY RUN — nic nie wysłano.')
            return int(bool(problems))
        # Do not silently skip validation failures during a sending run.
        if problems:
            print('Wysyłka przerwana: popraw błędy lub wybierz sprawdzoną domenę przez --domain.')
            return 1
        selected = ready[:1 if args.test_to else (args.limit or 1)]
        if args.send and not args.generic and not args.confirm_version_finding and any(not r.finding for r, _ in selected):
            p.error('Potwierdź prawdziwość wzmianki o wersji oprogramowania przez --confirm-version-finding albo wybierz --generic.')
        sender = os.environ.get('SMTP_USER', 'scout@codefellow.pl').strip()
        name = os.environ.get('SMTP_FROM_NAME', 'Bartłomiej Kędziora | Codefellow')
        if not EMAIL_RE.fullmatch(sender):
            raise ValueError('Niepoprawny SMTP_USER')
        if args.send:
            print(f'\nDo wysłania: {len(selected)} wiadomości. Wysyłaj wyłącznie po ręcznej weryfikacji raportów.')
            for report, _ in selected:
                print(f'  {report.domain} -> {report.email}')
            if input('Aby potwierdzić właściwą wysyłkę, wpisz SEND: ').strip() != 'SEND':
                print('Anulowano.'); return 0
        else:
            print(f'Wysyłka testowa wyłącznie do {args.test_to} (raport {selected[0][0].domain}).')
        password = os.environ.get('SMTP_PASSWORD') or getpass('Hasło SMTP: ')
        host = os.environ.get('SMTP_HOST', 'ssl0.ovh.net')
        port = int(os.environ.get('SMTP_PORT', '465'))
        with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=30) as smtp:
            smtp.login(sender, password)
            for index, (report, data) in enumerate(selected):
                msg = build_message(report, data, sender, name, signature, args.test_to, args.generic, html_signature, logo)
                key = canonical(report.domain)
                if args.send:
                    try:
                        db.execute('INSERT INTO deliveries(domain,email,pdf_sha256,message_id,status) VALUES (?,?,?,?,?)',
                                   (key, report.email, hashlib.sha256(data).hexdigest(), str(msg['Message-ID']), 'pending'))
                        db.commit()
                    except sqlite3.IntegrityError:
                        db.rollback()
                        print(f'SKIP {report.domain}: już zarezerwowana w logu')
                        continue
                try:
                    refused = smtp.send_message(msg, from_addr=sender, to_addrs=[args.test_to or report.email])
                    if refused:
                        raise smtplib.SMTPRecipientsRefused(refused)
                except Exception as exc:
                    if args.send:
                        db.execute("UPDATE deliveries SET status='uncertain', error=?, updated_at=CURRENT_TIMESTAMP WHERE domain=?", (str(exc)[:1000], key))
                        db.commit()
                    print(f'BŁĄD {report.domain}: {exc}. Sprawdź ręcznie przed ponowieniem.', file=sys.stderr)
                    return 1
                if args.send:
                    db.execute("UPDATE deliveries SET status='accepted', updated_at=CURRENT_TIMESTAMP WHERE domain=?", (key,))
                    db.commit()
                print(f'SMTP zaakceptował: {report.domain} -> {args.test_to or report.email}')
                if index + 1 < len(selected):
                    time.sleep(args.delay)
        return 0
    finally:
        if db is not None:
            db.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, smtplib.SMTPException, sqlite3.Error) as exc:
        print(f'BŁĄD: {exc}', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\nPrzerwano. Sprawdź log przed ponowną wysyłką.', file=sys.stderr)
        sys.exit(130)
