# Local scanner

Lokalny silnik pasywnej analizy stron. Wykorzystuje przeniesiony pipeline ZAP,
ProjectDiscovery httpx, wbudowane rozpoznawanie technologii, kontrole HTTP,
metadane TLS i korelację CVE. WhatWeb pominięto zgodnie z wyborem obecnego silnika.

## Uruchomienie

W WSL, w katalogu projektu:

```sh
cd /home/bartek/codeideas/local-scanner
mkdir -p output input
docker compose --profile cli build
docker compose up -d dns egress zap
docker compose run --rm scanner --url https://example.com/
```

Adres w przykładzie zastąp adresem przeznaczonym do sprawdzenia.
Plik .env ma wygenerowany lokalny klucz ZAP. Przy instalacji z .env.example
ustaw losowy klucz o długości co najmniej 32 znaków oraz LOCAL_UID i LOCAL_GID
zgodne z użytkownikiem posiadającym katalog output.

## Batch i wznowienie

CSV w input musi zawierać kolumnę `url`. Opcjonalna kolumna `gmina` trafia
do zestawienia w bazie. Pozostałe kolumny są zachowywane w manifeście i w
metadanych wyniku. Dla pojedynczego adresu nazwę można podać przez
`--url https://example.com/ --gmina "Nazwa gminy"`.

```sh
docker compose run --rm scanner --csv /input/example.csv
docker compose run --rm scanner --csv /input/example.csv --resume /output/batch-ID
```

CLI wypisuje ścieżkę partii. Przy wznowieniu należy użyć tej ścieżki i
identycznego wejścia. Ukończone adresy są pomijane. Przerwane i błędne
rekordy zostają wykonane ponownie. Identyczne URL-e w partii współdzielą
wynik, a wszystkie wiersze wejściowe pozostają w manifest.json.
Blokada katalogu output zapobiega jednoczesnemu używaniu wspólnej sesji ZAP.
Kody wyjścia: 0 ukończenie, 1 błąd, 130 przerwanie klawiaturą.

## Wyniki

Każda partia zawiera manifest.json oraz plik JSON dla każdego adresu.
Wynik zawiera schema_version, scan_id, url, metadata, created_at, finished_at,
duration_seconds, status, summary, findings, technologies, cves, http_checks,
checks, errors, tool_versions, dns_addresses i tls_metadata.
raw_zap zawiera przechwyconą odpowiedź HTTP i oryginalne alerty.
raw_tools zawiera wyniki modułów rozpoznawania, w tym stdout ProjectDiscovery.
Treści HTTP są zapisane jako base64 i podlegają dotychczasowym limitom pobierania.
Status completed może zawierać błędy poszczególnych modułów w errors.
Zapisy wykorzystują plik tymczasowy i atomową zamianę. Ponowne generowanie
raportów może korzystać bezpośrednio z tych plików.

## Docker

Usługi dns (CoreDNS), egress (Squid), zap i scanner. Zachowano izolowane sieci,
kontrolę publicznych adresów, proxy, klucz ZAP i limity zasobów.
Compose używa osobnych domyślnych podsieci 172.31.250–254 oraz nazwy local-scanner.
Cache CVE znajduje się w ./output/.cve-cache.sqlite3. Wyniki są w ./output.
Kontener scanner jest jednorazowym procesem CLI.

```sh
docker compose logs zap egress dns
docker compose down
```

Nie uruchamiano skanów ani testów automatycznych podczas wydzielania projektu.

## Baza wyników i filtrowanie

Wspólna baza SQLite znajduje się w output/scans.sqlite3. Każdy skan zapisuje
liczniki alertów oraz osobne rekordy alertów, błędów i kontroli HTTP. W tabeli
alerts pole page_url wskazuje stronę z alertem; każdy rekord odpowiada jednemu
wystąpieniu, więc można grupować po stronie, regule i poziomie ważności, aby
policzyć ostrzeżenia. `--details` zwraca także zestawienie `page_warnings`.
Pliki JSON pozostają dostępne do eksportu i wznowienia partii.
Domyślnie wyszukiwanie pokazuje najnowszy skan każdego URL-a.
Opcja --history obejmuje całą historię.

```sh
docker compose run --rm --no-deps --entrypoint python scanner -m app.results --details
docker compose run --rm --no-deps --entrypoint python scanner -m app.results --severity medium
docker compose run --rm --no-deps --entrypoint python scanner -m app.results --alert CSP
docker compose run --rm --no-deps --entrypoint python scanner -m app.results --with-errors
docker compose run --rm --no-deps --entrypoint python scanner -m app.results --check-status missing
docker compose run --rm --no-deps --entrypoint python scanner -m app.results --import-json
```

Filtry można łączyć. Dostępne są także --url, --status, --error, --check i --limit.
Import JSON jest powtarzalny i aktualizuje rekord o tym samym scan_id.

### Przeglądanie w PyCharm

W oknie **Database** wybierz źródło **Local Scanner — na żywo**. Łączy się
z lokalnym PostgreSQL pod `127.0.0.1:35432` jako `report_viewer` z prawem
odczytu. Usługa `report-sync` przenosi zatwierdzone wyniki i ścieżki PDF z
bazy SQLite w trakcie partii. W otwartej tabeli wybierz **Update Interval**
i ustaw np. **5 s**, aby odświeżać widok w tej samej sesji.

Aby uruchomić to połączenie na nowej instalacji, ustaw dwa różne losowe hasła
w `.env` według `.env.example` i uruchom z katalogu projektu
`docker compose --profile reports up -d --build report-sync`. Hasło do
użytkownika `report_viewer` pochodzi z `REPORT_DB_READER_PASSWORD`.
Opcjonalnie dodaj `reports` do `COMPOSE_PROFILES` w `.env`, aby zwykłe
uruchomienie skanera startowało też usługę raportową.

- `raporty` zawiera gminę, adres, status skanu, ścieżki PDF i JSON oraz
  liczniki alertów według ważności.
- `zagrozenia_wg_rodzaju` pokazuje liczbę wystąpień danej reguły i ważności
  w każdym skanie, razem z gminą i ścieżką PDF.

Ścieżki w kolumnach `sciezka_pdf` i `sciezka_json` są podane względem katalogu
`output`. Pusta ścieżka PDF oznacza, że raport PDF nie został jeszcze zapisany
dla danego skanu. Nazwa gminy pochodzi z `gmina` lub `client_name`; jeśli obu
brakuje, pole jest puste. Przykładowe zapytanie w konsoli PyCharm:

```sql
SELECT gmina, url, sciezka_pdf, rodzaj, waznosc, liczba
FROM zagrozenia_wg_rodzaju
ORDER BY gmina, url, liczba DESC;
```

Aby ręcznie wyeksportować zestawienie do pliku SQLite, wykonaj w katalogu projektu
`python3 -m app.results --output ./output --refresh-index`.

## Przekierowania

ZAP śledzi maksymalnie pięć przekierowań HTTP. Każdy kolejny adres przechodzi
walidację URL i DNS, a ruch nadal przechodzi przez Squida. JSON zachowuje
wejściowy url, final_url po udanym skanie i listę redirects. Pole https_to_http
oznacza przejście na nieszyfrowany HTTP. Moduły przeprowadzają sprawdzenia dla
adresu końcowego. Przekierowania nie wchodzą do liczników alertów ZAP.
Pętla, brak nagłówka Location lub odrzucony adres kończą zadanie błędem.

## Raporty PDF z zapisanych skanów

Generator raportów Stronoskop w `reports/` korzysta z pdfmake 0.2.20.
Wymaga Node.js 22.18 lub nowszego. Uruchom go z katalogu local-scanner:

```sh
npm --prefix reports ci
node reports/generate.mjs --input ./output/batch-ID --output ./output/pdf
node reports/generate.mjs --input ./output/batch-ID --output ./output/pdf --brief
```
Opcja `--brief` generuje obok pełnego raportu osobny plik `--brief.pdf`.
Wariant korzysta wyłącznie z zapisanego JSON-u i lokalnych danych; nie wymaga połączenia z siecią.
W skrócie raport wybiera najwyżej 3 CVE; gdy brak wiarygodnych dopasowań, pomija tę sekcję, a log podaje zero.

Możesz wskazać całe ./output. Generator odwiedza podkatalogi i pomija manifesty,
nieukończone skany oraz powtórzone identyfikatory skanów w jednym uruchomieniu.
Opcja --version full pozostaje obsługiwana dla zgodności. Oba warianty automatycznie
dobierają szczegółowość i limit stron. PDF interpretuje alerty ZAP zapisane w findings
i przedstawia kompletność danych dodatkowych. Nazwa pliku zawiera skrót
zawartości skanu: ponowne generowanie tych samych danych zastępuje ten sam PDF,
a zmienione dane tworzą nowy plik. Katalog wynikowy zawiera wyłącznie PDF-y;
ostrzeżenia i błędy generatora są wypisywane w konsoli.
Po zapisaniu PDF generator rejestruje ścieżkę w bazie skanów. Jeśli katalog PDF
znajduje się poza `output`, wskaż katalog z bazą opcją `--database-dir ./output`.

### Treść i układ raportów

Generator zachowuje dotychczasowy układ i oprawę wizualną:
ciemne tło, identyfikację marki, karty podsumowania, priorytety, część
szczegółową i numerację stron. Treści ustaleń, zaleceń, zakresu i ograniczeń
pochodzą z katalogu `knowledge/`; jeden plik PDF łączy je z tym układem.

Raport zawiera podsumowanie, wszystkie główne ustalenia z numerami U-01…,
obserwacje techniczne, kandydatów CVE, zakres kontroli i ograniczenia.
Na ostatniej stronie sekcja „Strona i kontakt” podaje e-mail i telefon w razie
pytań o raport, klikalny adres strony Codefellow i dane rejestrowe operatora.
Treść sekcji pochodzi z `knowledge/copy.yaml`.
Długie listy wystąpień są grupowane z reprezentatywnymi przykładami i podaną
liczbą. Generator nie zapisuje JSON-ów w katalogu PDF.

## HTTP API

API działa w osobnym kontenerze i uruchamia istniejący CLI skanera; `app/cli.py`
pozostaje bez zmian. W `.env` ustaw jeden losowy token współdzielony przez API
i front:

```sh
openssl rand -hex 32
```

Wynik zapisz jako `API_TOKEN`. API nie filtruje originów; dla frontów działających
w przeglądarce udostępnia `Access-Control-Allow-Origin: *`, więc nie trzeba
konfigurować listy domen. Uruchomienie:

```sh
docker compose up -d --build api nginx certbot
```

Nginx wystawia porty `80/443`, a Certbot automatycznie pobiera i odnawia TLS
dla `https://vps-4f804552.vps.ovh.ca/`. DNS tej nazwy musi wskazywać na ten VPS,
a porty `80` i `443` muszą być otwarte w firewallu OVH i VPS. API pozostaje
dostępne lokalnie na `127.0.0.1:8080`. Pierwsze wydanie certyfikatu trwa chwilę;
sprawdzisz je poleceniem `docker compose logs -f certbot nginx`.

Jeśli domena ma wskazywać inny VPS, zmień jej adres DNS i `API_DOMAIN`/`server_name`
w plikach `docker-compose.yml` i `proxy/*.conf`.
Oba endpointy przyjmują `POST` z JSON-em `{"domain":"example.com"}`. Podaj sam
publiczny hostname, bez schematu, portu ani ścieżki:

- `POST /api/v1/scan/json` — wynik skanera jako JSON.
- `POST /api/v1/scan/pdf` — PDF z istniejącego generatora raportów.

Każde żądanie skanowania wymaga nagłówka `X-API-Token` z wartością `API_TOKEN`.
Przykład:

```sh
curl https://vps-4f804552.vps.ovh.ca/api/v1/scan/json \
  -H 'Content-Type: application/json' \
  -H 'X-API-Token: <API_TOKEN>' \
  -d '{"domain":"example.com"}'

curl https://vps-4f804552.vps.ovh.ca/api/v1/scan/pdf \
  -H 'Content-Type: application/json' \
  -H 'X-API-Token: <API_TOKEN>' \
  -d '{"domain":"example.com"}' -o raport.pdf
```

Limit: 5 rozpoczętych skanów na hostname w ruchomym oknie 60 minut. Licznik
jest zapisany w `output/api-rate-limit.sqlite3` i przeżywa restart kontenera.
W danej chwili działa jeden skan; następne żądanie dostaje `503 scanner_busy`.
Nieudana próba po przyjęciu żądania również zużywa limit.

Token umieszczony w publicznym kodzie frontu jest widoczny dla jego użytkowników;
wspólny token nie zapewnia osobnej autoryzacji dla poszczególnych frontów.
