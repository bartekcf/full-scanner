#!/usr/bin/env python3
"""Build a complete, reviewable CSV for all local JST reports (no email sending)."""
import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

PREFIX = 'analiza_bezpieczenstwa_'
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')


def host(value):
    value = (value or '').strip()
    try:
        return (urlsplit(value if '://' in value else '//' + value).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


def canonical(domain):
    return domain.removeprefix('www.')


def write_csv(path, fields, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(fields)
        writer.writerows(records)


def export(pdfs, contacts, output):
    index = defaultdict(set)
    for row in contacts:
        domain = host(row.get('website'))
        if not domain:
            continue
        record = (domain, (row.get('email') or '').strip(), (row.get('office') or '').strip())
        normalized = canonical(domain)
        for key in {normalized, normalized.split('.')[0]}:
            index[key].add(record)

    records, review = [], []
    matched = 0
    for pdf in sorted(pdfs):
        stem = pdf.stem.lower()
        label = stem[len(PREFIX):] if stem.startswith(PREFIX) else ''
        candidates = sorted(index.get(canonical(label), set())) if label else []
        domain = email = reason = ''
        if not label:
            reason = 'Nieznany format nazwy pliku'
        elif not candidates:
            reason = 'Brak dopasowania w bazie'
        else:
            domains = {canonical(d) for d, _, _ in candidates}
            if len(domains) == 1:
                domain = candidates[0][0]
            # A single distinct contact is required; duplicate rows differing only in www are harmless.
            contacts_found = {(canonical(d), e.lower(), o.casefold()) for d, e, o in candidates}
            if len(contacts_found) != 1:
                reason = 'Niejednoznaczne dopasowanie'
            elif EMAIL_RE.fullmatch(candidates[0][1]):
                email = candidates[0][1]
            else:
                reason = 'Brak jednego poprawnego adresu e-mail'
        path = str(pdf.resolve())
        records.append((domain, email, path))
        if reason:
            review.append((domain, email, path, reason, ' | '.join(f'{d}: {e} ({o})' for d, e, o in candidates)))
        else:
            matched += 1
    write_csv(output, ['domain', 'email', 'path_to_pdf'], records)
    review_path = output.with_name(output.stem + '_do_weryfikacji.csv')
    write_csv(review_path, ['domain', 'email', 'path_to_pdf', 'reason', 'candidates'], review)
    return matched, len(review), review_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pdf-dir', type=Path, default=Path('output/urzedy-white-scout'))
    parser.add_argument('--contacts', type=Path, default=Path('input/baza_urzedy_kontakty.csv'))
    parser.add_argument('--output', type=Path, default=Path('output/urzedy_wysylka.csv'))
    parser.add_argument('--overwrite', action='store_true', help='Pozwól nadpisać CSV (również ręcznie uzupełnione dane).')
    args = parser.parse_args()
    if not args.pdf_dir.is_dir():
        parser.error(f'Nie ma katalogu: {args.pdf_dir}')
    if not args.contacts.is_file():
        parser.error(f'Nie ma bazy kontaktów: {args.contacts}')
    review_path = args.output.with_name(args.output.stem + '_do_weryfikacji.csv')
    if not args.overwrite and (args.output.exists() or review_path.exists()):
        parser.error('Plik wynikowy już istnieje. Użyj --overwrite tylko jeśli chcesz go nadpisać.')
    pdfs = [p for p in args.pdf_dir.rglob('*') if p.is_file() and p.suffix.lower() == '.pdf']
    if not pdfs:
        parser.error('Brak plików PDF w katalogu')
    with args.contacts.open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if not {'website', 'email', 'office'}.issubset(reader.fieldnames or []):
            parser.error('Baza CSV musi zawierać kolumny website,email,office')
        contacts = list(reader)
    matched, missing, review = export(pdfs, contacts, args.output)
    print(f'Znalezione PDF: {len(pdfs)}')
    print(f'Dopasowane po nazwie: {matched}')
    print(f'Do ręcznej weryfikacji: {missing}')
    print(f'Pełna lista: {args.output.resolve()}')
    print(f'Lista braków: {review.resolve()}')
    print('Przed wysyłką sprawdź domeny raportów i adresatów.')


if __name__ == '__main__':
    main()
