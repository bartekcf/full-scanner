#!/usr/bin/env python3
"""Copy report JSON files matching the software-house export filter."""

from __future__ import annotations

import argparse
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path


def export_jsons(database_path: Path, output_dir: Path) -> int:
    source_root = database_path.resolve().parent
    database_uri = f"{database_path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(database_uri, uri=True)) as database:
        rows = database.execute(
            """
            SELECT DISTINCT sciezka_json AS json_path
            FROM raporty
            WHERE created_at >= ? AND wysokie >= ?
              AND sciezka_json IS NOT NULL AND TRIM(sciezka_json) <> ''
            ORDER BY json_path
            """,
            ("2026-11-25", 1),
        ).fetchall()

    output_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for (json_path,) in rows:
        relative_path = Path(json_path)
        if relative_path.is_absolute():
            raise ValueError(f"Ścieżka JSON nie jest względna: {json_path}")

        source = (source_root / relative_path).resolve()
        try:
            safe_relative_path = source.relative_to(source_root)
        except ValueError as error:
            raise ValueError(f"Ścieżka JSON wychodzi poza output: {json_path}") from error
        if not source.is_file():
            raise FileNotFoundError(f"Nie znaleziono pliku JSON: {source}")

        destination = output_dir / safe_relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied += 1

    return copied


def main() -> int:
    project_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description=(
            "Kopiuje JSON-y z raporty dla created_at >= 2026-11-25 "
            "i wysokie >= 1."
        )
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=project_root / "output" / "raporty.sqlite3",
        help="Baza SQLite z widokiem raporty (domyślnie output/raporty.sqlite3).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=project_root / "output" / "hr-softwarehouses",
        help="Katalog docelowy (domyślnie output/hr-softwarehouses).",
    )
    args = parser.parse_args()

    if not args.database.is_file():
        parser.error(f"Nie znaleziono bazy SQLite: {args.database}")
    try:
        copied = export_jsons(args.database, args.output_dir)
    except (OSError, sqlite3.Error, ValueError) as error:
        parser.error(str(error))

    print(f"Skopiowano {copied} plików JSON do {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())