"""Collect public website links from the FirmyPolska IT directory.
Usage: pip install requests beautifulsoup4
       python collect_firmypolska.py
Run in the directory containing input/softwarehouses.csv.
"""
import csv
import re
import time
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

BASE = 'https://firmypolska.pl'
START = BASE + '/it/'
AGENT = 'DirectoryLinkCollector/1.0'
DELAY = 1.5
INPUT = Path('input/softwarehouses.csv')
OUTPUT = Path('input/firmypolska_nowe.csv')
# City and pagination links only; excludes individual company profiles.
PATH = re.compile(r'^/it/(?:[^/]+/(?:strona-\d+/)?)?$')


def host(url):
    try:
        parsed = urlsplit(url if '://' in url else 'https://' + url)
        return (parsed.hostname or '').lower().removeprefix('www.').rstrip('.')
    except ValueError:
        return ''


def read_existing():
    if not INPUT.exists():
        raise SystemExit(f'Missing {INPUT}; run from project root.')
    with INPUT.open(encoding='utf-8-sig', newline='') as f:
        return {host(r.get('ur') or r.get('url') or '') for r in csv.DictReader(f)}


def main():
    existing = read_existing()
    session = requests.Session()
    session.headers['User-Agent'] = AGENT
    robots = RobotFileParser()
    response = session.get(BASE + '/robots.txt', timeout=25)
    if response.status_code == 404:
        robots.parse([])
    else:
        response.raise_for_status()
        robots.parse(response.text.splitlines())
    delay = max(DELAY, robots.crawl_delay(AGENT) or robots.crawl_delay('*') or 0)
    queue = deque([START])
    seen = {START}
    found = set()
    errors = []
    completed = 0
    while queue:
        url = queue.popleft()
        if not robots.can_fetch(AGENT, url):
            print('Disallowed:', url)
            continue
        time.sleep(delay)
        try:
            response = session.get(url, timeout=25)
            if response.status_code in (403, 429):
                print('Access limited; stopping and saving partial results.')
                break
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
        except requests.RequestException as exc:
            errors.append(url)
            print('Error:', url, exc)
            continue
        completed += 1
        for a in soup.select('a[href]'):
            link = urljoin(response.url, a['href'])
            parts = urlsplit(link)
            if parts.scheme not in ('http', 'https'):
                continue
            domain = host(link)
            if domain == 'firmypolska.pl':
                path = parts.path.rstrip('/') + '/'
                if PATH.fullmatch(path):
                    next_url = BASE + path
                    if next_url not in seen:
                        seen.add(next_url)
                        queue.append(next_url)
                continue
            # In this directory the company website anchor is labelled with its hostname.
            label = a.get_text(' ', strip=True)
            if domain and '.' in domain and host(label) == domain and domain not in existing:
                found.add(domain)
        print(f'Pages: {completed} | queued: {len(queue)} | new domains: {len(found)} | {url}')
        # Preserve partial progress even if the process is stopped later.
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        with OUTPUT.open('w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ur'])
            writer.writerows([['https://' + d] for d in sorted(found)])
    print(f'Done: {len(found)} new domains; {completed} pages; {len(errors)} request errors.')
    print('Output:', OUTPUT)
    if errors:
        print('Failed URLs:', *errors, sep='\n')


if __name__ == '__main__':
    main()
