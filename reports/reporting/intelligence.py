"""Offline advisory and upstream lifecycle interpretation for saved scans."""
from collections import defaultdict
from datetime import date
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

from .privacy import clean

_CATALOG = Path(__file__).resolve().parents[2] / 'knowledge' / 'lifecycle.json'
_VERSION = re.compile(r'v?[0-9]{1,9}(?:\.[0-9]{1,9}){0,5}(?:[A-Za-z][0-9]{0,4}|[-+~][A-Za-z0-9][A-Za-z0-9.+~-]{0,39})?', re.I)
_NUMERIC = re.compile(r'v?([0-9]{1,9}(?:\.[0-9]{1,9}){0,5})', re.I)
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,12}', re.I)
_GHSA = re.compile(r'GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}', re.I)
_OSV_ID = re.compile(r'(?:[A-Z][A-Z0-9]{1,20}-[A-Za-z0-9][A-Za-z0-9.-]{0,75})')
_STATUS = {
    'version_match': 'Zgodność wersji', 'conditional': 'Zależne od warunków',
    'insufficient': 'Brak danych', 'out_of_range': 'Poza zapisanym zakresem',
    'patched': 'Poprawka odnotowana',
}
_SEVERITY = {'critical': 'Krytyczna', 'high': 'Wysoka', 'medium': 'Średnia', 'moderate': 'Średnia',
             'low': 'Niska', 'none': 'Brak', 'info': 'Informacyjna'}
_BOUNDS = {'versionStartIncluding': ('≥', lambda n: n >= 0), 'versionStartExcluding': ('>', lambda n: n > 0),
           'versionEndIncluding': ('≤', lambda n: n <= 0), 'versionEndExcluding': ('<', lambda n: n < 0)}
_COMPARE = {'>': lambda n: n > 0, '>=': lambda n: n >= 0, '<': lambda n: n < 0,
            '<=': lambda n: n <= 0, '=': lambda n: n == 0}
_URL = re.compile(r'(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>]+')
_SECRET = re.compile(r'(?i)\b(?:authorization|cookie|set-cookie|password|passwd|token|secret|session|csrf|nonce|api[_-]?key)\s*[:=]\s*[^;,\r\n]+')
_MODULE = re.compile(r'(?i)\b(?:mod_[a-z0-9_]{1,34}|ngx_[a-z0-9_]{1,34}_module|[a-z][a-z0-9_]{1,30}\.[a-z][a-z0-9_]{1,30}(?=\s+(?:directive|option|setting)|\s*=))\b')
_OS = re.compile(r'(?i)\b(?:windows|linux|freebsd|openbsd|netbsd|macos|solaris|unix|android)\b')
_CONFIG = re.compile(r'(?i)\b(?:if|when|only|requires?|enabled|configured|using|with)\b')
_CONFIG_WORD = re.compile(r'(?i)\b(?:modules?|extensions?|plugins?|settings?|directives?|configured|configuration|enabled|build|compiled|option)\b')
_APACHE_ADVISORY = re.compile(r'https?://httpd\.apache\.org/security/vulnerabilities_(22|24)\.html#(CVE-[0-9]{4}-[0-9]{4,12})', re.I)
_PHP_CHANGELOG = re.compile(r'https?://(?:www\.)?php\.net/ChangeLog-([578])\.php(?:#([0-9]+\.[0-9]+\.[0-9]+))?', re.I)
_PHP_ADVISORY = re.compile(r'https://github\.com/php/php-src/security/advisories/(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})', re.I)


@lru_cache(maxsize=1)
def _knowledge():
    data = json.loads(_CATALOG.read_text(encoding='utf-8'))
    aliases = {
        alias.casefold(): key
        for key, product in data['products'].items()
        for alias in (key, product['name'], *product.get('aliases', ()))
    }
    return data, aliases


def _list(value):
    return value if isinstance(value, list) else ()


def _records(scan, key):
    return (item for item in _list(scan.get(key)) if isinstance(item, dict))


def _text(value, limit=160):
    if not isinstance(value, str):
        return ''
    return clean(_SECRET.sub('[dane usunięte]', _URL.sub('[adres pominięty]', value)), limit)


def _product(value):
    name = _text(value, 68)
    data, aliases = _knowledge()
    key = aliases.get(name.casefold(), name.casefold())
    return key, data['products'].get(key, {}).get('name', name)


def _version(value):
    if isinstance(value, str) and len(value) <= 100 and _VERSION.fullmatch(value.strip()):
        return value.strip().lstrip('vV').lower()
    return ''


def _numeric(value):
    match = _NUMERIC.fullmatch(value) if isinstance(value, str) else None
    return tuple(map(int, match[1].split('.'))) if match else ()


def _release(value):
    """Stable dotted versions only. Package revisions/prereleases need an ecosystem-specific comparator."""
    parts = _numeric(value)
    if not parts:
        raise ValueError('unsupported version')
    return parts + (0,) * (6 - len(parts))


def _compare(version, bound):
    left, right = _release(version), _release(bound)
    return (left > right) - (left < right)


def _compatible(first, second):
    if first == second:
        return True
    left, right = _numeric(first), _numeric(second)
    width = min(len(left), len(right))
    return bool(width and len(left) != len(right) and left[:width] == right[:width])


def _sources(record):
    result = {source.casefold() for source in _list(record.get('sources')) if isinstance(source, str)}
    if isinstance(record.get('source'), str):
        result.add(record['source'].casefold())
    return result


def _source_version(technology):
    sources = _sources(technology)
    status = technology.get('version_status')
    return bool(sources and (status in ('declared', 'verified') or (status == 'fingerprinted' and len(sources) > 1)))


def _withdrawn(record):
    if any(record.get(k) for k in ('withdrawn', 'withdrawn_at')):
        return True
    return any(isinstance(record.get(k), str) and record[k].lower().strip() in {'rejected', 'withdrawn', 'revoked'}
               for k in ('advisory_status', 'vulnStatus', 'status'))


def _record_product(record):
    return _product(record.get('technology_name') or record.get('product'))


def _id(prefix, *parts):
    return prefix + '-' + hashlib.sha256('\0'.join(parts).encode()).hexdigest()[:16]


def _technology_observations(scan, alert_versions):
    groups = {}

    def group(key, product):
        return groups.setdefault(key, {'product': product, 'tech': set(), 'http': set(), 'cve': set(),
                                       'observed': set(), 'conflict': False})

    for technology in _records(scan, 'technologies'):
        key, product = _product(technology.get('name'))
        if not key:
            continue
        target = group(key, product)
        version = _version(technology.get('version'))
        versions = [_version(item) for item in _list(technology.get('observed_versions'))]
        target['conflict'] |= bool(technology.get('version_conflict'))
        target['observed'].update(item for item in [version, *versions] if item)
        if version and _source_version(technology):
            target['tech'].add(version)

    for item in alert_versions:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            continue
        key, product = _product(item[0])
        version = _version(item[1])
        if key and version:
            target = group(key, product)
            target['observed'].add(version)
            target['http'].add(version)

    for record in _records(scan, 'cves'):
        if _withdrawn(record):
            continue
        key, product = _record_product(record)
        if not key:
            continue
        target = group(key, product)
        version = _version(record.get('detected_version'))
        if version:
            target['observed'].add(version)
            if _sources(record) & {'nvd', 'osv', 'github security advisories', 'ghsa'}:
                target['cve'].add(version)

    for key, group_data in groups.items():
        # A correlation usually repeats a fingerprint and is not independent evidence.
        reliable = (group_data['tech'] | group_data['http']) or group_data['cve']
        candidates = reliable or group_data['observed']
        selected = max(candidates, key=lambda v: (len(v), v), default='')
        conflict = group_data['conflict'] or any(not _compatible(selected, v) for v in candidates)
        yield key, group_data['product'], selected if not conflict else '', bool(reliable), conflict


def _cycle(entry, version, as_of, verified_on):
    # Builds with vendor suffixes can still reveal a branch, but prereleases do not.
    match = re.match(r'^[0-9]+(?:\.[0-9]+)*', version)
    parts = match[0].split('.') if match else []
    width = entry.get('components', 2)
    branches = entry.get('branches', {})
    branch = next(('.'.join(parts[:n]) for n in range(len(parts), width - 1, -1)
                   if '.'.join(parts[:n]) in branches), '')
    period = branches.get(branch, {})
    if not period or re.search(r'(?i)(?:alpha|beta|(?:^|[.\d-])rc|snapshot|preview|dev)', version):
        return 'unknown', '', entry.get('unknown_detail', 'Nie ma zweryfikowanego harmonogramu dla tej gałęzi.')
    today = as_of.isoformat()
    if period.get('ended_from') and today >= period['ended_from']:
        end = period.get('end_label', period['ended_from'])
        return 'ended', period.get('source', 'schedule'), f'Projekt zakończył wsparcie gałęzi {branch} ({end}).'
    if period.get('last_supported') and not period.get('ended_from') and today > period['last_supported']:
        return 'ended', period.get('source', 'schedule'), f'Wsparcie gałęzi {branch} trwało do {period["last_supported"]}.'
    known_supported = (
        period.get('start', '9999') <= today and (
            (period.get('observed') and today <= verified_on)
            or today <= period.get('last_supported', '')
            or (not period.get('last_supported') and today < period.get('ended_from', ''))
        )
    )
    if known_supported:
        phase = 'wsparcie ograniczone' if today > period.get('active_until', '9999') else 'wsparcie'
        deadline = period.get('end_label') or period.get('last_supported') or period.get('ended_from')
        span = f' (termin zakończenia: {deadline})' if deadline else ''
        return 'supported', period.get('source', 'schedule'), f'Gałąź {branch}: {phase} projektu{span}.'
    return 'unknown', period.get('source', 'schedule'), f'Harmonogram nie rozstrzyga statusu gałęzi {branch} na dzień oceny.'


def technology_support(scan, as_of: date | None, *, alert_versions=()):
    """Return lifecycle rows; alert_versions contains HTTP declaration (product, version) pairs."""
    data, _ = _knowledge()
    as_of = as_of if as_of is not None else date.today()
    rows = []
    for key, product, version, sourced, conflict in _technology_observations(scan, alert_versions):
        entry = data['products'].get(key, {})
        status, source = 'unknown', ''
        if conflict:
            detail = 'Zapis zawiera sprzeczne oznaczenia wersji; nie da się jednoznacznie ustalić gałęzi.'
        elif not version:
            detail = 'Zapis nie zawiera wersji pozwalającej ustalić gałąź.'
        elif not sourced:
            detail = 'Zapis nie zawiera wiarygodnego źródła wersji lub nie potwierdza odczytu z kilku źródeł.'
        else:
            status, source, detail = _cycle(entry, version, as_of, data['verified_on'])
        source_link = entry.get('sources', {}).get(source or 'schedule')
        links = [source_link] if source_link else []
        if status == 'ended':
            impact = 'Projekt nie publikuje już poprawek dla tej gałęzi. Dostawca pakietu może utrzymywać własne.'
            recommendation = 'Sprawdzić poprawki dla pełnego wydania pakietu u dostawcy. Jeśli ich nie zapewnia, zaplanować migrację.'
            links.append(data['backport_policy'])
        elif status == 'supported':
            impact = ''
            recommendation = 'Porównać zainstalowane wydanie z aktualizacjami dostawcy.'
        else:
            impact = recommendation = ''
        rows.append({'id': _id('tech', key), 'product': product, 'version': version, 'status': status,
                     'status_label': {'ended': 'Koniec wsparcia projektu (EOL)', 'supported': 'Wsparcie projektu',
                                      'unknown': 'Nie ustalono'}[status], 'detail': detail,
                     'impact': impact, 'recommendation': recommendation, 'links': links})
    order = {'ended': 0, 'supported': 1, 'unknown': 2}
    return sorted(rows, key=lambda row: (order[row['status']], row['product'].casefold()))


def _candidate_identifiers(record):
    names, urls = [], []
    sources = _sources(record)
    osv_id = record.get('osv_id')
    advisories = _list(record.get('advisory_ids'))
    values = (record.get('cve_id'), record.get('ghsa_id'), osv_id, *advisories)
    for value in values:
        if not isinstance(value, str):
            continue
        if _CVE.fullmatch(value):
            name = value.upper()
            urls.append(('NVD', 'https://nvd.nist.gov/vuln/detail/' + name))
            if value == osv_id or ('osv' in sources and not osv_id and not advisories):
                urls.append(('OSV', 'https://osv.dev/vulnerability/' + name))
        elif _GHSA.fullmatch(value):
            name = 'GHSA-' + value[5:].lower()
            urls.append(('GitHub', 'https://github.com/advisories/' + name))
            if value == osv_id or ('osv' in sources and not osv_id):
                urls.append(('OSV', 'https://osv.dev/vulnerability/' + name))
        elif (value == osv_id or 'osv' in sources) and _OSV_ID.fullmatch(value):
            name = value
            urls.append(('OSV', 'https://osv.dev/vulnerability/' + name))
        else:
            continue
        if name not in names:
            names.append(name)
    return names, urls


def _advisory_links(product_key, names, urls, record):
    data, _ = _knowledge()
    official = data['products'].get(product_key, {}).get('advisories', {})
    urls.extend(('Komunikat projektu', official[name]) for name in names if name in official)
    # Rebuild direct vendor links from recognized official formats.
    # Never copy arbitrary references or vendor_advisories into the document.
    for value in _list(record.get('vendor_advisories')):
        if not isinstance(value, str) or len(value) > 200:
            continue
        url = ''
        if product_key == 'apache' and (match := _APACHE_ADVISORY.fullmatch(value)):
            identifier = match[2].upper()
            if identifier in names:
                url = f'https://httpd.apache.org/security/vulnerabilities_{match[1]}.html#{identifier}'
        elif product_key == 'php':
            if match := _PHP_ADVISORY.fullmatch(value):
                url = 'https://github.com/php/php-src/security/advisories/GHSA-' + match[1][5:].lower()
            elif match := _PHP_CHANGELOG.fullmatch(value):
                url = 'https://www.php.net/ChangeLog-' + match[1] + '.php' + ('#' + match[2] if match[2] else '')
        if url:
            urls.append(('Komunikat projektu', url))
    return [{'label': label, 'url': url} for label, url in list(dict.fromkeys(urls))[:6]]


def _alternatives(results):
    if True in results:
        return True
    return False if results and None not in results else None


def _cpe(value):
    if not isinstance(value, str) or len(value) > 480:
        return ()
    parts = tuple(re.split(r'(?<!\\):', value))
    return parts if len(parts) == 13 and parts[:2] == ('cpe', '2.3') else ()


def _cpe_text(fields, bounds):
    bits = [f'= {fields[5]}'] if fields[5] not in {'*', '-'} and _version(fields[5]) else []
    bits.extend(f'{op} {bound}' for key, (op, _) in _BOUNDS.items() if (bound := _version(bounds.get(key))))
    return ', '.join(bits)


def _cpe_range(version, fields, bounds):
    try:
        if fields[5] == '-':
            return None
        checks = [] if fields[5] == '*' else [_compare(version, fields[5]) == 0]
        checks.extend(compare(_compare(version, bounds[key])) for key, (_, compare) in _BOUNDS.items() if key in bounds)
    except ValueError:
        return None
    return all(checks)


def _cpe_context(fields):
    notes = []
    for i, label in ((6, 'aktualizacja'), (7, 'edycja'), (8, 'język'), (9, 'wariant'),
                     (10, 'platforma'), (11, 'architektura'), (12, 'wariant dodatkowy')):
        if fields[i] != '*':
            notes.append(f'{label}: {fields[i]}' if fields[i] != '-' else f'{label}: nie dotyczy w CPE')
    return notes


def _nvd_rules(version, spec):
    target = _cpe(spec.get('target_cpe'))
    if not target:
        return None, False, []
    matches = []

    def prerequisites(leaves, nodes=(), depth=0):
        notes = []
        for leaf in leaves:
            fields = _cpe(leaf.get('criteria')) if isinstance(leaf, dict) else ()
            if fields:
                kind = 'system' if fields[2] == 'o' else 'komponent'
                version_bounds = _cpe_text(fields, leaf)
                label = f'{kind}: {fields[4]}'
                notes.append(f'{label} ({version_bounds})' if version_bounds else label)
        if depth < 8:
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                if node.get('negate') is True:
                    notes.append('sprawdź wykluczenia NVD')
                notes.extend(prerequisites(_list(node.get('cpeMatch')),
                                           (*_list(node.get('nodes')), *_list(node.get('children'))), depth + 1))
        return tuple(dict.fromkeys(notes))

    def walk(nodes, conditions=(), depth=0):
        if depth > 32:
            return
        for node in _list(nodes):
            if not isinstance(node, dict) or node.get('negate') is True:
                continue
            leaves = [item for item in _list(node.get('cpeMatch')) if isinstance(item, dict)]
            nested = [*_list(node.get('nodes')), *_list(node.get('children'))]
            op = str(node.get('operator', 'OR')).upper()
            is_and = op == 'AND'
            joined = conditions
            if is_and or op != 'OR':
                joined += ('kontekst konfiguracji NVD',)

            for leaf in leaves:
                fields = _cpe(leaf.get('criteria'))
                if leaf.get('vulnerable') is not True or not fields or fields[2:5] != target[2:5]:
                    continue
                notes = (*joined, *_cpe_context(fields))
                if is_and:
                    notes += prerequisites((item for item in leaves if item is not leaf), nested)
                matches.append((_cpe_range(version, fields, leaf), notes, _cpe_text(fields, leaf)))
            for child in nested:
                siblings = (item for item in nested if item is not child)
                walk([child], joined + (prerequisites(leaves, siblings) if is_and else ()), depth + 1)

    walk(spec.get('configurations'))
    decision = _alternatives([result for result, _, _ in matches])
    matching = [(notes, bounds) for result, notes, bounds in matches if result is True]
    unconditional = [bounds for notes, bounds in matching if not notes]
    conditional = bool(matching and not unconditional)
    details = list(dict.fromkeys(note for notes, _ in matching for note in notes)) if conditional else []
    bounds = dict.fromkeys(unconditional or [bound for _, bound in matching] or [bound for _, _, bound in matches])
    details.extend(bound for bound in bounds if bound)
    return decision, conditional, details


def _legacy_nvd(version, expression, technology_cpe, product_key):
    leaf = {}
    terms = expression.split(';')
    fields = _cpe(terms[0].strip())
    expected = _cpe(technology_cpe)
    if not fields or (expected and expected[2:5] != fields[2:5]):
        return None, False, []
    cpe_key, _ = _product(fields[4])
    if not expected and cpe_key != product_key:
        return None, False, []
    for term in terms[1:]:
        key, sep, bound = term.strip().partition('=')
        if not sep or key not in _BOUNDS or key in leaf:
            return None, False, []
        leaf[key] = bound.strip()
    notes = _cpe_context(fields)
    bounds = _cpe_text(fields, leaf)
    return _cpe_range(version, fields, leaf), bool(notes), notes + ([bounds] if bounds else [])


def _osv_events(version, events):
    result, opening, closed, labels = False, None, None, []
    if not events:
        return None, []
    try:
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                return None, []
            kind, bound = next(iter(event.items()))
            if kind == 'introduced' and opening is None:
                if closed is not None and (bound in ('0', '*') or _compare(bound, closed) < 0):
                    return None, []
                opening = bound
                if bound != '0':
                    _release(bound)
                    labels.append(f'≥ {bound}')
            elif kind in ('fixed', 'last_affected', 'limit') and opening is not None:
                if opening != '0' and _compare(opening, bound) > 0:
                    return None, []
                upper = '<=' if kind == 'last_affected' else '<'
                above = opening == '0' or _compare(version, opening) >= 0
                result |= above and _COMPARE[upper](_compare(version, bound))
                labels.append(f'{"≤" if upper == "<=" else "<"} {bound}')
                opening, closed = None, bound
            else:
                return None, []
        if opening is not None:
            result |= opening == '0' or _compare(version, opening) >= 0
    except ValueError:
        return None, []
    return result, labels


def _osv_rules(version, spec):
    results, notes = [], []
    conditional = False
    for affected in _list(spec.get('affected')):
        if not isinstance(affected, dict):
            continue
        versions = _list(affected.get('versions'))
        if version in [_version(item) for item in versions]:
            results.append(True)
            notes.append(f'= {version}')
        elif versions:
            results.append(False)
        for item in _list(affected.get('ranges')):
            if not isinstance(item, dict) or item.get('type') not in ('SEMVER', 'ECOSYSTEM', 'UNIVERSAL'):
                results.append(None)
                continue
            result, labels = _osv_events(version, _list(item.get('events')))
            results.append(result)
            notes.extend(labels)
        for field in ('ecosystem_specific', 'database_specific'):
            contextual = _structured_conditions(affected.get(field))
            conditional |= bool(contextual)
            notes.extend(contextual)
    return _alternatives(results), conditional, list(dict.fromkeys(notes))


def _legacy_osv(version, expression):
    events = []
    for term in expression.split(','):
        kind, _, value = term.strip().partition(' ')
        if not value or not _numeric(value.strip()):
            return None, False, []
        events.append({kind: value.strip()})
    result, notes = _osv_events(version, events)
    return result, False, notes


def _github_range(version, expression, ecosystem):
    if not isinstance(expression, str) or not expression or len(expression) > 512:
        return None, []
    results, notes = [], []
    version_parts = _numeric(version)
    if not version_parts:
        return None, []
    if ecosystem == 'npm' and len(version_parts) != 3:
        return None, []
    for alternative in expression.split('||'):
        value = alternative.strip()
        hyphen = re.fullmatch(r'(v?[0-9.]+)\s+-\s+(v?[0-9.]+)', value, re.I)
        terms = list(hyphen and ('>=' + hyphen[1], '<=' + hyphen[2]) or
                     re.split(r'[\s,]+', re.sub(r'([<>=^~])\s+', r'\1', value)))
        checks, labels = [], []
        try:
            for term in terms:
                m = re.fullmatch(r'(<=|>=|<|>|=|\^|~)?(.*)', term)
                op, bound = m[1] or '=', m[2]
                wildcard = re.fullmatch(r'(\d+(?:\.\d+)*)(?:\.[xX*])+', bound)
                if op == '=' and bound in ('*', 'x', 'X'):
                    checks.append(True)
                elif op == '=' and wildcard and ecosystem in ('npm', 'composer'):
                    prefix = _numeric(wildcard[1])
                    if not prefix:
                        raise ValueError
                    checks.append(version_parts[:len(prefix)] == prefix)
                    labels.append(f'{wildcard[1]}.x')
                elif op in ('^', '~'):
                    parts = _numeric(bound)
                    if ecosystem != 'npm' or not parts or len(parts) > 3:
                        raise ValueError
                    if op == '~':
                        pivot = min(1, len(parts) - 1)
                    else:
                        pivot = next((i for i, part in enumerate(parts) if part), len(parts) - 1)
                    upper = '.'.join(map(str, (*parts[:pivot], parts[pivot] + 1)))
                    checks.append(_compare(version, bound) >= 0 and _compare(version, upper) < 0)
                    labels.extend([f'≥ {bound}', f'< {upper}'])
                elif op in _COMPARE:
                    parts = _numeric(bound)
                    if ecosystem == 'npm' and op == '=' and 0 < len(parts) < 3:
                        checks.append(version_parts[:len(parts)] == parts)
                        labels.append(f'{bound}.x')
                    elif ecosystem == 'npm' and op != '=' and 0 < len(parts) < 3:
                        # Node's partial comparison has distinct bound semantics.
                        raise ValueError
                    else:
                        checks.append(_COMPARE[op](_compare(version, bound)))
                        labels.append(f'{op} {bound}')
                else:
                    raise ValueError
        except ValueError:
            results.append(None)
            continue
        results.append(bool(checks) and all(checks))
        notes.append(', '.join(labels))
    return _alternatives(results), [note for note in notes if note]


def _structured_conditions(value):
    if not isinstance(value, dict):
        return []
    notes = []
    for key, label in (('os', 'system'), ('platform', 'platforma'), ('platforms', 'platforma'),
                       ('module', 'moduł'), ('modules', 'moduły'), ('configuration', 'konfiguracja'),
                       ('configurations', 'konfiguracja')):
        if key not in value:
            continue
        item = value[key]
        parts = [_text(v, 56) for v in (item if isinstance(item, list) else [item])[:6]]
        details = ', '.join(filter(None, parts))
        notes.append(f'{label}: {details}' if details else label)
    return notes


def _description_conditions(description):
    modules = list(dict.fromkeys(_MODULE.findall(description)))
    platforms = list(dict.fromkeys(value.lower() for value in _OS.findall(description)))
    notes = ([f'moduły/dyrektywy: {", ".join(modules[:5])}'] if modules else [])
    if platforms and _CONFIG.search(description):
        notes.append(f'platformy w opisie: {", ".join(platforms[:5])}')
    if _CONFIG_WORD.search(description) and _CONFIG.search(description):
        notes.append('porównaj aktywne moduły i ustawienia z komunikatem')
    return notes


def _comparison(record, version, technology_cpe, product_key):
    structured = [spec for spec in _list(record.get('applicability')) if isinstance(spec, dict)]
    if structured:
        results, flags, notes = defaultdict(list), [], []
        for spec in structured:
            source = spec.get('source')
            if source == 'NVD':
                result, conditional, details = _nvd_rules(version, spec)
            elif source == 'OSV':
                result, conditional, details = _osv_rules(version, spec)
            elif source == 'GHSA':
                comparisons = [_github_range(version, expression, spec.get('ecosystem'))
                               for expression in _list(spec.get('ranges'))]
                result = _alternatives([match for match, _ in comparisons])
                conditional, details = False, [item for _, bounds in comparisons for item in bounds]
            else:
                continue
            results[source].append(result)
            flags.append(result is True and conditional)
            notes.extend(details)
        values = {_alternatives(items) for items in results.values()}
        result = next(iter(values)) if len(values) == 1 else None
        return result, any(flags), notes

    text = record.get('affected_range')
    if not isinstance(text, str) or not text or len(text) > 1024:
        return None, False, []
    sources = _sources(record)
    if text.startswith('cpe:2.3:') and 'nvd' in sources:
        result, conditional, notes = _legacy_nvd(version, text, technology_cpe, product_key)
        # Legacy NVD kept only one CPE leaf; low confidence also flagged AND/negate.
        if record.get('confidence') == 'low':
            conditional = True
            notes.insert(0, 'porównaj pełną konfigurację NVD')
        return result, conditional, notes
    if 'osv' in sources and re.match(r'^(introduced|fixed|last_affected|limit) ', text):
        return _legacy_osv(version, text)
    if sources & {'github security advisories', 'ghsa'}:
        result, notes = _github_range(version, text, record.get('ecosystem'))
        return result, False, notes
    return None, False, []


def _cvss(value, version, severity):
    try:
        value = float(value) if isinstance(value, (str, int, float)) and not isinstance(value, bool) else None
        value = value if value is not None and 0 <= value <= 10 else None
    except (ValueError, OverflowError):
        value = None
    cvss_version = _text(version, 10)
    severity_key = severity.lower() if isinstance(severity, str) else ''
    if severity_key not in _SEVERITY and cvss_version in {'3.0', '3.1', '4.0'} and value is not None:
        severity_key = 'critical' if value >= 9 else 'high' if value >= 7 else 'medium' if value >= 4 else 'low' if value else 'none'
    return value, cvss_version if value is not None else '', _SEVERITY.get(severity_key, '—')


def _evaluated_row(record, product_key, version, technology_cpe, conflict):
    source_description = _text(record.get('description'), 1500)
    description = source_description
    if len(description) > 210:
        description = description[:210].rsplit(' ', 1)[0] + '…'
    conditions = _structured_conditions(record.get('conditions')) + _structured_conditions(record)
    conditions += _description_conditions(source_description)
    backport = record.get('backport_status')
    backport_verified = backport in ('confirmed', 'patched', 'backported', 'confirmed_patched', 'confirmed_backport',
                                     'backport_confirmed')
    backport_missing = backport in ('not_patched', 'confirmed_not_patched', 'not_backported')
    compare = bool(not conflict and len(_numeric(version)) >= 3)
    if compare:
        result, contextual, ranges = _comparison(record, version, technology_cpe, product_key)
    else:
        result, contextual, ranges = None, False, []
    note = ''
    if not conflict and version and backport_verified:
        status, note = 'patched', 'Odnotowano poprawkę dostawcy.'
    elif result is False:
        status = 'out_of_range'
    elif result is True:
        status = 'conditional' if contextual or conditions else 'version_match'
        if backport_missing:
            note = 'Zapis wskazuje brak poprawki dostawcy.'
        if contextual and not conditions:
            conditions.append('pozostałe warunki środowiska w komunikacie')
    else:
        status = 'insufficient'
        if conflict:
            note = 'Zapis wskazuje różne wersje.'
        elif not compare:
            note = 'Brak pełnej wersji porównywalnej z zakresem.'
        else:
            note = 'Zapis nie rozstrzyga zakresu dla tego wydania.'
    # Keep the matching bounds and specific prerequisites ahead of general advice.
    bounds = [_text(item.replace('<', '‹').replace('>', '›'), 72) for item in ranges]
    details = '; '.join(dict.fromkeys(filter(None, [*bounds, *conditions])))
    if len(details) > 175:
        details = details[:175].rsplit(' ', 1)[0] + '…'
    reasons = ' '.join(filter(None, [note, details])) or 'Szczegóły w komunikacie źródłowym.'
    score, cvss_version, severity = _cvss(record.get('cvss_score'), record.get('cvss_version'), record.get('severity'))
    return {'status': status, 'status_label': _STATUS[status], 'conditions': reasons, 'description': description,
            'cvss_score': score, 'cvss_version': cvss_version, 'severity': severity}


def cve_candidates(scan):
    """Return technology/version groups, keeping each valid input row, even with no CVSS."""
    technologies, conflicts = {}, set()
    for technology in _records(scan, 'technologies'):
        key, _ = _product(technology.get('name'))
        version = _version(technology.get('version'))
        if _source_version(technology) and version:
            technologies.setdefault(key, []).append((version, technology.get('cpe')))
        if technology.get('version_conflict'):
            conflicts.add(key)
    groups = {}
    for record in _records(scan, 'cves'):
        key, product = _record_product(record)
        if not key:
            key, product = 'unknown', 'Nieustalona technologia'
        detected = _version(record.get('detected_version'))
        known = technologies.get(key, [])
        version, cpe = max(known, key=lambda entry: (len(entry[0]), entry[0]), default=(detected, ''))
        conflict = key in conflicts or any(not _compatible(version, item) for item, _ in known)
        if detected and version and not _compatible(version, detected):
            conflict = True
        if conflict:
            version = detected
        group_key = (key, version)
        group = groups.setdefault(group_key, {'id': _id('cve', *group_key), 'product': product, 'version': version,
                                              'count': 0, 'rows': []})
        group['count'] += 1
        names, urls = _candidate_identifiers(record)
        if not names or _withdrawn(record):
            continue
        row = _evaluated_row(record, key, version, cpe, conflict)
        group['rows'].append({'identifier': names[0], **row, 'links': _advisory_links(key, names, urls, record)})
    order = {status: index for index, status in enumerate(_STATUS)}
    result = [group for group in groups.values() if group['rows']]
    for group in result:
        group['rows'].sort(key=lambda row: (order[row['status']], -(row['cvss_score'] if row['cvss_score'] is not None else -1),
                                            row['identifier']))
    return sorted(result, key=lambda group: (order[group['rows'][0]['status']], group['product'].casefold(), group['version']))
