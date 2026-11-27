#!/usr/bin/env python3
"""Jednorazowa migracja nazw PDF i ścieżek CSV. Domyślnie tylko podgląd."""
import argparse
import csv
import os
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREFIX = 'Analiza_bezpieczenstwa_'
# Nazwy wyprowadzone z domen w dostarczonym CSV; www nie ma znaczenia.
NAMES = {
    'e-perlejewo.pl': 'perlejewo',
    'eulhowek.pl': 'ulhowek',
    'gmina.tarnow.pl': 'gmina_tarnow',
    'gminacisna.pl': 'gmina_cisna',
    'gminakruszwica.pl': 'gmina_kruszwica',
    'gminapilzno.pl': 'gmina_pilzno',
    'gminaplaterowka.pl': 'gmina_platerowka',
    'katywroclawskie.pl': 'katy_wroclawskie',
    'lipcereymontowskie.pl': 'lipce_reymontowskie',
    'miasto.hrubieszow.pl': 'miasto_hrubieszow',
    'new.marciszow.pl': 'marciszow',
    'nowa.sosnowica.pl': 'sosnowica',
    'nowasucha.pl': 'nowa_sucha',
    'powiat.starachowice.pl': 'powiat_starachowice',
    'powiat.tarnow.pl': 'powiat_tarnow',
    'powiatszczycienski.pl': 'powiat_szczycienski',
    'powiatwielicki.pl': 'powiat_wielicki',
    'sierpc.starostwo.gov.pl': 'powiat_sierpc',
    'soleckujawski.pl': 'solec_kujawski',
    'uggozdowo.bip.org.pl': 'gozdowo',
    'uglaczna.bip.doc.pl': 'laczna',
    'ugnowemiasto.pl': 'nowe_miasto',
    'ugwejherowo.pl': 'gmina_wejherowo',
    'um.bialapodlaska.pl': 'miasto_biala_podlaska',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', type=Path, default=ROOT / 'input/urzedy_wysylka_final.csv')
    parser.add_argument('--pdf-dir', type=Path, default=ROOT / 'output/urzedy-white-scout')
    parser.add_argument('--apply', action='store_true', help='Wykonaj migrację; bez tego tylko podgląd.')
    args = parser.parse_args()
    csv_path = args.csv.resolve()
    pdf_dir = args.pdf_dir.resolve(strict=True)
    with csv_path.open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        if not {'domain', 'email', 'path_to_pdf'} <= set(fields):
            raise ValueError('Brak wymaganych kolumn CSV.')
        rows = list(reader)
    if not rows:
        raise ValueError('CSV jest pusty.')
    changes, errors, old_paths, targets = [], [], set(), set()
    for i, row in enumerate(rows, start=2):
        domain = (row.get('domain') or '').strip().lower().removeprefix('www.').rstrip('.')
        raw_path = (row.get('path_to_pdf') or '').strip()
        if not domain or not raw_path:
            errors.append(f'Wiersz {i}: brak domeny lub ścieżki.')
            continue
        old = Path(raw_path)
        if not old.is_absolute():
            old = (ROOT / old)
        old = old.absolute()
        if old.parent.resolve() != pdf_dir or old.is_symlink() or old.suffix.lower() != '.pdf' or not old.name.startswith(PREFIX):
            errors.append(f'Wiersz {i}: nieoczekiwana ścieżka {old}')
            continue
        new = old.with_name(PREFIX + NAMES[domain] + '.pdf') if domain in NAMES else old
        if old in old_paths or new in targets:
            errors.append(f'Wiersz {i}: zduplikowana ścieżka {old} / {new}')
        old_paths.add(old)
        targets.add(new)
        if not old.is_file():
            errors.append(f'Brak pliku: {old}')
        if new != old:
            if new.exists() or new.is_symlink():
                errors.append(f'Plik docelowy już istnieje: {new}')
            changes.append((row, old, new))
    for _, old, new in changes:
        print(f'{old.name} -> {new.name}')
    print(f'\nRaporty: {len(rows)} | do zmiany: {len(changes)} | błędy: {len(errors)}')
    if errors:
        for error in errors:
            print('BŁĄD:', error, file=sys.stderr)
        print('Przerwano. Nie zmieniono plików ani CSV.', file=sys.stderr)
        return 1
    if not args.apply:
        print('PODGLĄD — bez zmian. Dodaj --apply, aby wykonać migrację.')
        return 0
    if not changes:
        print('Brak zmian do wykonania.')
        return 0
    backup = csv_path.with_name(csv_path.name + '.bak.' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    shutil.copy2(csv_path, backup)
    completed = []
    temp = None
    try:
        # Najpierw przygotuj nowy CSV, potem zmień nazwy PDF i atomowo podmień CSV.
        for row, old, new in changes:
            row['path_to_pdf'] = str(new)
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='', dir=csv_path.parent, delete=False) as f:
            temp = Path(f.name)
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        shutil.copymode(csv_path, temp)
        for _, old, new in changes:
            if new.exists() or new.is_symlink():
                raise FileExistsError(new)
            old.rename(new)
            completed.append((old, new))
        os.replace(temp, csv_path)
    except BaseException:
        for old, new in reversed(completed):
            try:
                if old.exists() or old.is_symlink():
                    raise FileExistsError(old)
                new.rename(old)
            except OSError as exc:
                print(f'BŁĄD COFANIA: {new} -> {old}: {exc}', file=sys.stderr)
        raise
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)
    print(f'Zmieniono {len(completed)} nazw PDF i zaktualizowano {csv_path}.')
    print(f'Kopia oryginalnego CSV: {backup}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, csv.Error) as exc:
        print(f'BŁĄD: {exc}', file=sys.stderr)
        sys.exit(1)
