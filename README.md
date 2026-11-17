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

CSV w input musi zawierać kolumnę url. Pozostałe kolumny są zachowywane
w manifeście oraz metadanych wyniku.

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

Wspólna baza SQLite znajduje się w output/scans.sqlite3. Kolejne skany zapisują
w niej pełny JSON, liczniki alertów oraz osobne rekordy alertów, błędów i kontroli
HTTP. Pliki JSON pozostają dostępne do eksportu i wznowienia partii.
Domyślnie wyszukiwanie pokazuje najnowszy skan każdego URL-a.
Opcja --history obejmuje całą historię. --details dodaje nazwy alertów i błędy.
Wyniki są sortowane według liczby alertów wysokich, średnich i niskich.

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

## Przekierowania

ZAP śledzi maksymalnie pięć przekierowań HTTP. Każdy kolejny adres przechodzi
walidację URL i DNS, a ruch nadal przechodzi przez Squida. JSON zachowuje
wejściowy url, final_url po udanym skanie i listę redirects. Pole https_to_http
oznacza przejście na nieszyfrowany HTTP. Moduły przeprowadzają sprawdzenia dla
adresu końcowego. Przekierowania nie wchodzą do liczników alertów ZAP.
Pętla, brak nagłówka Location lub odrzucony adres kończą zadanie błędem.

## Raporty PDF z zapisanych skanów

Generator w reports korzysta z szablonu AudytorAI i pdfmake 0.2.20.
Wymaga Node.js 22.18 lub nowszego. Uruchom go z katalogu local-scanner:

```sh
npm --prefix reports ci
node reports/generate.mjs --input ./output/batch-ID --output ./output/pdf
```

Możesz wskazać całe ./output. Generator odwiedza podkatalogi i pomija manifesty,
nieukończone skany oraz powtórzone identyfikatory skanów w jednym uruchomieniu.
Opcja --version full pozostaje obsługiwana dla zgodności. Oba warianty automatycznie
dobierają szczegółowość i limit stron. PDF interpretuje alerty ZAP zapisane w findings
i przedstawia kompletność danych dodatkowych. Nazwa odbiorcy pochodzi z kolumny client_name w CSV
(przenoszonej do metadata); bez nazwy używana jest domena końcowa. Można też
podać recipient, organization lub name w metadata. Nazwa pliku zawiera skrót
zawartości skanu: ponowne generowanie tych samych danych zastępuje ten sam PDF,
a zmienione dane tworzą nowy plik. Katalog wynikowy zawiera wyłącznie PDF-y;
ostrzeżenia i błędy generatora są wypisywane w konsoli.

### Treść i układ raportów

Generator zachowuje układ i oprawę wizualną pierwszego raportu AudytorAI:
ciemne tło, identyfikację marki, karty podsumowania, priorytety, część
szczegółową i numerację stron. Treści ustaleń, zaleceń, zakresu i ograniczeń
pochodzą z katalogu `knowledge/`; jeden plik PDF łączy je z tym układem.

Raport zawiera podsumowanie, wszystkie główne ustalenia z numerami U-01…,
obserwacje techniczne, kandydatów CVE, zakres kontroli, ograniczenia i dane
wykonawcy. Długie listy wystąpień są grupowane z reprezentatywnymi przykładami
i podaną liczbą. Generator nie zapisuje JSON-ów w katalogu PDF.
