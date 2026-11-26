"""Local exclusions for CVE identifiers misrepresented by upstream data."""

IGNORED_CVE_IDS = frozenset({"CVE-2007-3205"})


def is_ignored_cve(record: object) -> bool:
    if not isinstance(record, dict):
        return False

    identifiers = [record.get("cve_id"), record.get("osv_id"), record.get("ghsa_id")]
    for field in ("advisory_ids", "aliases"):
        values = record.get(field)
        if isinstance(values, list):
            identifiers.extend(values)

    return any(
        isinstance(identifier, str)
        and identifier.strip().upper() in IGNORED_CVE_IDS
        for identifier in identifiers
    )
