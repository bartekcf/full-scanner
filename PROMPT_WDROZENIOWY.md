# Zadanie: kompleksowa przebudowa generatora raportów AudytorAI

Pracujesz w istniejącym repozytorium generatora raportów. Masz załączony katalog `knowledge/`, osiem przykładowych PDF-ów oraz, jeśli są w repozytorium, ich źródłowe JSON-y. Najpierw odczytaj kod i schemat danych. Następnie faktycznie zaimplementuj zmiany, uruchom testy i wygeneruj przykłady. Nie kończ na planie. Nie zmieniaj skanera, zakresu żądań ani jego zabezpieczeń. Nie ponawiaj skanowania zewnętrznych stron w celu testowania generatora. Jeżeli JSON-ów nie ma, użyj lokalnych fikstur zgodnych z rzeczywistym schematem i jawnie oznacz ograniczenie; nie odtwarzaj pełnych danych na podstawie skróconych PDF-ów.

## 1. Cel i granice

Ma powstać **jeden kompletny PDF na skan**, zrozumiały dla kierownika urzędu i przydatny dla informatyka. Nie twórz osobnej wersji technicznej, wersji premium, eksportu dla klienta ani obowiązkowego załącznika JSON. Wewnętrzny JSON pozostaje źródłem danych. Raport ma dostarczać samodzielną wartość; nie może odsyłać do pliku, do którego odbiorca nie ma dostępu. Dane techniczne istotne dla wniosków umieść w tym samym PDF. Nie obiecuj pełnego audytu, ręcznej weryfikacji ani potwierdzenia podatności, jeśli nie wykonano takich czynności.

Docelowe wrażenie: profesjonalna, rzeczowa informacja od wykonawcy badającego stronę, nie eksport ZAP, reklama lub dashboard SaaS. Pisz po polsku, bez zwrotów na „Ty”, bez sztucznego straszenia. Unikaj sloganów, zbędnych metafor i powtórzeń. Nie wprowadzaj scoringu 0–100, wykresów udziału alertów, odliczania ani sztucznych terminów napraw.

## 2. Architektura i katalog wiedzy

Włącz dostarczone YAML-e jako wersjonowany katalog do istniejącej architektury (np. reporting/knowledge). Nie buduj bazy SQL ani nie uzależniaj działania od LLM. Rozdziel: adapter danych źródłowych → normalizacja → dopasowanie katalogu → klasyfikacja i grupowanie → model dokumentu → render PDF. Dopuszczalne są inne nazwy modułów, zgodne z repozytorium. Zachowaj dotychczasowe wejście CLI i kompatybilność ze starszymi JSON-ami w miarę możliwości; nie zmieniaj kontraktu skanera na ślepo.

Pliki z `source: zap` zawierają reguły, `policy.yaml` zawiera zasady, `copy.yaml` gotowe teksty i konfigurację prezentacji. Waliduj je przy starcie (safe_load, schemat, poprawne typy, unikalny key, jednoznaczne dopasowania, istniejące grupy, priorytety, nieznane placeholdery, poprawne URL dokumentacji). Reguły nie są wykonywalnym kodem; override'y są deklaratywne, realizuj je jawnie w Pythonie, nie przez eval. Traktuj pliki z repozytorium jako zaufaną konfigurację, a wyniki skanowania jako niezaufane dane.

Dopasowanie: preferuj dokładny alertRef z ZAP; pluginId + dokładna znormalizowana nazwa alertu jako drugi krok. Liczby zamieniaj na string, nie obcinaj sufiksu wariantu. Jeśli alertRef i nazwa/plugin są sprzeczne, prześlij do kolejki niejednoznacznych mapowań (nie przypisuj dowolnej treści). Nie mapuj wspólnego pluginId 10055, 10038, 10020, 10054, 10035, 10036 lub 20020 wyłącznie na pierwszy wariant. Przy nieznanym alertRef nie stosuj na siłę podobnej nazwy. Nazwy przetwarzaj przez Unicode NFKC, trim, collapse whitespace i casefold. Nie dopasowuj po fragmencie, chyba że dodasz udokumentowaną, precyzyjną regułę z testem. W przypadku nazw zlokalizowanych użyj dokładnego alertRef, a jawne aliasy rozszerz na podstawie prawdziwych danych. Katalog startowy nie obejmuje całego ZAP.

Nieznane reguły: użyj polskiego fallbacku z policy.yaml, zachowaj oryginalną nazwę i kod w technicznych metadanych oraz wyłącznie bezpieczny dowód. Nie wyświetlaj „braku mapowania”. Dla alertów high/critical nadaj pilną weryfikację; medium daj do szczegółów, low do pozostałych obserwacji bez wniosku o podatności, informational do informacji. Generuj lokalny log/listę brakujących mapowań, nie dodatkowy PDF. Niewidoczne w PDF alerty nie są automatycznie uznane za fałszywe; ich dane pozostają w źródle i wewnętrznych logach.

## 3. Model raportu

Zdefiniuj jawny, testowalny model: metadata (target, final_url, scanned_at, timezone, report_id, generator_version, method), coverage (status, checks, errors), findings (group, stable key, title, priority, verification_status, scanner risk/confidence, observation, impact, recommendation, verification, sanitized evidence, instances, source refs, references), technical_observations, cve_candidates, summary. Każdy wniosek musi być powiązany z wejściową obserwacją. Nie twórz danych pozornych. Zachowaj różnicę między nieobecnym polem, pustą listą oraz potwierdzonym brakiem nagłówka. Pusty evidence nie potwierdza braku czegokolwiek. Jeśli nie posiadasz surowych nagłówków, przypisz podstawę: „Automatyczna obserwacja ZAP; brak zapisu surowych nagłówków w danych raportu”. Nie pisz, że widziałeś surową odpowiedź. Odpowiedź potwierdzona przez moduł może być osobno oznaczona, ale nigdy nie podnoś wyniku do potwierdzonej podatności na podstawie pasywnego alertu.

Priorytet działania jest niezależny od ryzyka i pewności ZAP. Wysoki alert z niską pewnością ma mieć etykietę „Pilna weryfikacja”, a nie „potwierdzona luka”. Nie nadawaj wysokiego ryzyka całej witrynie. Jeśli nieznana klasa ryzyka, oznacz brak danych; nigdy nie zastępuj jej zerem. Zastosuj default_priority i override'y z policy.yaml, kontekst potwierdzony przez człowieka tylko w przypadku jawnego pola recenzji i zachowanego uzasadnienia. Nie wywnioskuj, że cookie jest sesyjne po samej nazwie; może to być wskazówka do weryfikacji.

Grupuj według obszaru, zachowując odrębne warianty i ich dowody. W szczególności: CSP jako jeden rozdział z podpunktami; cookie atrybuty według nazwy/domeny/ścieżki, jeśli dostępne; SRI i zewnętrzne skrypty kojarz tylko gdy wiadomo, że dotyczą tego samego zasobu; identyfikację wersji i CVE według produktu i wykrytej wersji. Nie łącz odmiennych problemów tylko dlatego, że znajdują się pod tym samym adresem. Dedup: preferuj źródłowy identyfikator instancji; w razie jego braku przygotuj stabilny klucz z wariantu, URL, metody, parametru/elementu i dowodu, nie ignorując różnych cookies lub zasobów. Przechowuj oryginalną liczbę alertów, liczbę instancji i odrębną liczbę grup. Liczba dla odbiorcy ma jasno opisywać, co liczy. Nie traktuj sumy alertów jako liczby luk. Nie przekalkulowuj severity na procent ryzyka.

Szum: timestamp, Modern Web Application, Session Management Response Identified, typowe zewnętrzne JS i cache umieszczaj w kompaktowej sekcji informacji technicznych. Nie usuwaj alertu na podstawie samej nazwy. Jeśli pojawia się udokumentowany wrażliwy kontekst, nadaj odpowiadający mu priorytet. Nie ogłaszaj nieznanych reguł bezpiecznymi. Zachowaj wszystkie istotne obserwacje w PDF; duże listy jednorodnych wystąpień przedstaw zgrupowane z liczbą i reprezentatywnymi, zanonimizowanymi przykładami. Nie ukrywaj istotnych alertów tylko po to, by zmieścić się w limicie stron.

## 4. Teksty i struktura PDF – jeden dokument

Użyj dosłownych tekstów z copy.yaml, tam gdzie pasują do stanu danych. Teksty z katalogu są bazą redakcyjną, a nie obowiązkiem skopiowania wszystkich pól. Połącz zdania wspólne dla grupy; nie powtarzaj ograniczeń pod każdym alertem. Jeśli brakuje wartości placeholdera, pomiń całe zdanie lub zastosuj bezpieczną wersję; nigdy nie drukuj `{target}` / `None` / `undefined`. Dołącz polskie nazwy grup, nie angielski słownik ZAP. Rzeczowe terminy techniczne i oryginalne nazwy alertów pozostają w metadanych.

### Pierwsza strona

Ma zaczynać się od logo/nazwy wykonawcy (mały rozmiar), daty, tytułu **Wstępna analiza bezpieczeństwa strony internetowej**, domeny, faktycznie analizowanego adresu oraz metody. Nie osobna okładka. Nie duplikuj domeny bez powodu. Godzina i pełne ID skanu mogą być w metadanych pod tytułem lub na końcu.

1. Wstęp: „W dniu {date} przeprowadziliśmy wstępną analizę publicznie dostępnej strony internetowej {target}. Sprawdziliśmy wybrane elementy jej konfiguracji na podstawie danych dostępnych bez logowania.” Zmień czas i zakres, jeśli skan nie zebrał danych lub dotyczył innej metody.
2. Wnioski: dobierz najwyższy rzeczywiście występujący priorytet i szablon podsumowania z copy.yaml. Wstaw maksymalnie kilka konkretnych polskich obszarów/ustaleń, a nie ogólniki. Nie twórz wniosków o obszarach, których nie badano. W przypadku błędów kontroli umieść informację na pierwszej stronie. Jeśli nie udało się zebrać użytecznych danych, pokaż ten fakt zamiast pozytywnego komunikatu. Przy częściowym skanie bez alertów pisz wyłącznie o wykonanych kontrolach.
3. Tabela „Najważniejsze ustalenia”: obszar | zaobserwowany element | zalecane działanie. Maksymalnie 4–6 najważniejszych wierszy; odsyłaj do numeru ustalenia w tym samym raporcie, nie do JSON. Przykład: „Nagłówki przeglądarki | Brak deklaracji ograniczającej osadzanie | Zweryfikować konfigurację (U-02)”.
4. Krótka rekomendacja: dobierz wariant actions z copy.yaml. Bez CTA. Jedno zdanie wyjaśniające automatyczny charakter ustaleń.

### Dalsze strony – szczegółowe ustalenia

Użyj numerów U-01, U-02… przypisanych deterministycznie i używanych w całym dokumencie. Sortowanie: priorytet, stabilna kolejność grup, stabilny klucz. Dla każdego obszaru pokaż tytuł, priorytet, ustalenie, znaczenie i zalecenie oraz podstawę techniczną. Weryfikacja po stronie administratora ma być zwięzła i konkretna. Dla grup wielowariantowych zastosuj krótkie podpunkty z odrębnymi dowodami, a wspólne znaczenie i zalecenia zbierz raz. Nie wymuszaj jednej strony na alert.

Przykładowa treść CSP (tylko jeśli skan faktycznie wskazał brak nagłówka):
**Brak nagłówka polityki bezpieczeństwa treści (CSP)** – W analizowanej odpowiedzi HTTP nie stwierdzono nagłówka Content-Security-Policy. Brak ten ogranicza dodatkową ochronę przeglądarki przed niepożądanymi skryptami i może zwiększać skutki innych podatności. Zalecamy przygotowanie polityki CSP dopasowanej do zasobów strony i jej stopniowe wdrożenie. Podstawa: adres odpowiedzi, obserwacja ZAP, reguła 10038-1 albo rzeczywisty identyfikator wejściowy, pewność detekcji. Nie stwierdzono XSS na tej podstawie.

Przykładowa treść CSP, jeśli polityka istnieje: „Polityka CSP wymaga przeglądu. W analizowanej konfiguracji zgłoszono następujące elementy: [rzeczywiście zgłoszone warianty]. Zalecamy doprecyzowanie dozwolonych źródeł z uwzględnieniem funkcji i integracji serwisu.” Nie używaj tekstu o braku CSP dla istniejącej polityki. Wyświetl konkretne dyrektywy, jeśli są w dowodzie. Nie ujawniaj nonce.

Przykładowa treść CSRF: „W analizowanym kodzie formularza nie rozpoznano standardowego tokena CSRF. Jeżeli formularz wykonuje operację w kontekście użytkownika, brak skutecznej ochrony może umożliwić wymuszenie niezamierzonego działania. Zalecamy sprawdzenie obsługi formularza po stronie serwera.” Pokaż ID lub metodę tylko jeśli znane; dopisz niski confidence, jeśli taki jest wynik. Nie twierdź, że formularz służy do logowania, płatności lub operacji na danych, jeśli tego nie ustalono.

Przykładowa treść PHP: „Odpowiedź HTTP zawiera informację wskazującą na wersję PHP {detected_version}. Skaner powiązał ją z potencjalnymi podatnościami. Zalecamy potwierdzenie rzeczywistej wersji oraz stanu poprawek przez dostawcę hostingu.” Pokaż niski confidence, jeśli występuje. Informację o zakończeniu wsparcia dodawaj tylko z wiarygodnego źródła lub jawnie zweryfikowanego katalogu cyklu życia, a nie na podstawie numeru wersji lub CVE; uwzględniaj backporty dostawców. Nie przedstawiaj 199 dopasowań CVE jako 199 podatności.

### Pozostałe obserwacje techniczne

Kompaktowa tabela: obserwacja | kontekst | liczba wystąpień (jeśli znana) | zalecenie, jeśli ma zastosowanie. Wiersze informacyjne nie mogą sugerować, że wymagają napraw. Jeśli zbiór jest pusty, pomiń sekcję. Wyjaśnij, że publiczne daty/znaczniki czasu same w sobie nie oznaczają problemu, jeśli takie alerty wystąpiły. W tym samym dokumencie podaj wszystkie ważne dane techniczne i źródła, nie powtarzaj oryginalnych akapitów angielskiej dokumentacji.

### Zakres i wyniki kontroli

Tabela: kontrola | status | uwagi. Pokazuj tylko kontrole rzeczywiście znane z wejścia. Oddziel wynik kontroli (wykonana / częściowa / nie udała się / niewykonana / poza zakresem / brak danych) od ustalenia bezpieczeństwa. Brak alertu nie oznacza zaliczenia testu. Nie ustawiaj „OK” dla nieznanego wyniku. Dopuszczalne wiersze (jeśli dostępne): dostępność HTTP/HTTPS, przekierowania, nagłówki, cookies, formularze, zasoby, TLS, fingerprinting, CVE. Dla TLS użyj informacji o certyfikacie tylko gdy zebrane; nie opisuj HTTPS jako prawidłowego certyfikatu bez weryfikacji. Dla CVE opisz liczbę kandydatów tylko jeśli ma znaczenie; podaj produkt, wersję, status weryfikacji, źródło i ewentualne identyfikatory w tym samym PDF. Nie twórz listy rzekomo potwierdzonych CVE. Jeżeli kandydatów jest bardzo dużo, pokaż powiązanie z produktem i najważniejsze zweryfikowane informacje, oddzielnie liczbę niepotwierdzonych dopasowań.

Na końcu podaj zakres i ograniczenia: gotowy tekst z copy.yaml, skorygowany zgodnie z rzeczywiście wykonaną metodą. Dla nieukończonych modułów użyj polskich opisów z policy.yaml i zachowaj kod błędu wewnętrznie. Nie drukuj surowych stack trace'ów. Nie powielaj „nie dowodzi włamania” pod każdym punktem; dodaj je tylko tam, gdzie ma znaczenie dla interpretacji. Jeśli narzędzie nie wykonało analizy, nie używaj formy „sprawdziliśmy”.

### Informacje o wykonawcy

Jeden neutralny blok na ostatniej stronie: „Analiza została przygotowana przez AudytorAI. W przypadku pytań dotyczących ustaleń przedstawionych w raporcie można skontaktować się z wykonawcą analizy.” Wstaw wyłącznie rzeczywiste dane kontaktowe z konfiguracji/repozytorium. Nie wymyślaj danych, certyfikatów ani nazwy prawnej. Jeśli brak kontaktu, pomiń brakujące pola i zgłoś braki przed dystrybucją.

Opcjonalny akapit z copy.yaml o rozszerzeniu do audytu, domyślnie wyłączony. Można włączyć tylko gdy sposób komunikacji z odbiorcą na to pozwala; nie rób drugiego typu PDF. Bez cennika, przycisku, kodu rabatowego, nacisku, sugerowania certyfikacji ani twierdzenia, że tylko my możemy usunąć problem. Wynik ma być użyteczny także wtedy, gdy odbiorca wybierze własnego administratora. Nie implementuj masowej wysyłki ani marketingu w ramach tego zadania.

## 5. Design i druk

A4 pionowo, białe tło, marginesy 18–22 mm, treść 10.5–11 pt, nagłówki 14–20 pt, tytuł 24–28 pt, stopka 8–9 pt. Inter/Source Sans 3 lub dostępna czytelna lokalna czcionka z kompletem polskich znaków; nie pobieraj fontów w trakcie renderowania. Kolor główny #18364A, tekst #1F2937, tekst pomocniczy #52606D, linie #DCE3E8, tło tabel #F3F6F8. Czerwony #A82020 i bursztynowy #8A5200 wyłącznie jako małe znaczniki priorytetu, zawsze z opisem tekstowym. Brak ciemnych pełnostronicowych powierzchni, neonów, gradientów, tarcz dekoracyjnych, wykresów kołowych, surowej sumy alertów w dużym KPI. Logo dyskretne. Stopka: nazwa, badana domena, strona X / Y, jeśli renderer to obsługuje. Zachowaj brand, ale nie imituj instytucji państwowej. Nazwa pliku: domena--data--analiza.pdf z bezpiecznym slugiem i ochroną przed kolizją.

Preferuj obecny silnik PDF, jeśli można osiągnąć wymagania. HTML/CSS z autoescapingiem jest dobrym wyborem, ale nie zmieniaj technologii bez potrzeby. Tekst ma być przeszukiwalny, nie rasteryzowany. Zapewnij powtarzanie nagłówków tabel, kontrolowane przenoszenie nagłówków z kolejnym tekstem, zawijanie długich adresów i kodu, brak nakładania się treści/stopki. Nie obcinaj dowodów bez informacji o skrócie; zamiast pełnych wielkich nagłówków cytuj właściwe dyrektywy, bez sekretów. Nie wymuszaj długości – zwykle 2–4 strony, więcej jeśli wymaga tego liczba istotnych ustaleń. Nie dodawaj pustych stron. Sprawdź czytelność na ekranie i na wydruku czarno-białym.

## 6. Bezpieczeństwo generatora i prywatność

Nie pobieraj zasobów przez renderer z adresów pochodzących ze skanów. Wyłącz dostęp rendererowi do sieci i ogranicz dostęp do plików lokalnych do wymaganych zasobów. Nie pozwalaj na HTML/JS w danych wejściowych; escapuj tekst, a URL w linkach ogranicz do http/https i bezpiecznej formy. Odfiltruj Authorization, Cookie, wartości Set-Cookie, tokeny CSRF, identyfikatory sesji, CSP nonce, hasła, dane osobowe i sekrety z dowodów, parametrów URL, fragmentów HTML i logów. Dla cookies pokaż nazwę/atrybuty, bez wartości. Dla formularzy ID/metodę i pozbawiony sekretów action; dla CSP pojedyncze dyrektywy z redakcją nonce. Jeśli nie potrafisz bezpiecznie wydzielić informacji, nie renderuj surowego dowodu i wyjaśnij, że dostępny zapis nie pozwala na bezpieczne przytoczenie. Sanitacja następuje przed budową modelu prezentacyjnego; źródło pozostaje bez zmian. Używaj limitów wejścia i renderowania. Nie zapisuj niezaufanych nazw jako ścieżek.

## 7. Testy i kryteria akceptacji

Przygotuj testy jednostkowe dopasowania każdego wpisu, w tym wariantów 10055, 10038, 10054 i 20020, sprzecznych identyfikatorów, braku pól, nieznanych reguł, unicode i numerów jako int/string. Sprawdź dedup i grupowanie, rozróżnienie priorytetu i confidence, częściowy skan bez alertów, brak danych, nieznany risk, błędny TLS, puste/duże listy, bezpieczeństwo renderowania, maskowanie sekretów, brak połączeń sieciowych oraz spójność wierszy z podsumowaniem. W testach używaj fikstur i nie odpalaj skanu cudzych domen. Testy PDF: tekst przeszukiwalny, poprawne polskie znaki, brak placeholderów, brak pustych stron, zawijanie, sekcje i numeracja. Wygeneruj PDF-y, wyrenderuj wszystkie strony do PNG i obejrzyj przynajmniej pierwszy i ostatni arkusz każdego dokumentu oraz wszystkie strony z tabelami i długimi dowodami. Popraw zauważone problemy, ponów test.

Regresja na ośmiu przykładach, jeśli są źródłowe JSON-y:
- Żuromin: 9 alertów, 43 kandydatów CVE; brak CSP i clickjacking oraz inne ustalenia; nie nazywaj kandydatów podatnościami.
- Baranów Sandomierski: 10 alertów, SRI dla 3 wystąpień, zewnętrzne zasoby bez alarmizmu.
- Bielsk Podlaski: 6 alertów, brak CSP, 2 obserwacje SRI; właściwy URL końcowy.
- BIP Bratian: 5 alertów, 2 wystąpienia CSRF, niski confidence, formularz ustawieniaStrony jako wskazówka, nie dowód ataku.
- Wilczyn: 11 alertów; CSP wildcard, script-src unsafe-inline i style-src unsafe-inline jako jeden obszar z trzema wariantami; cookies jako odrębna grupa.
- Wolbórz: 41 alertów, 22 znaczniki czasu; w oryginalnym PDF pominięto jedną grupę, odzyskaj ją wyłącznie z JSON, nie zgaduj.
- Załuski: 71 alertów, 61 znaczników czasu; cztery warianty CSP w jednym obszarze; nie eksponuj 71 jako liczby luk.
- BIP Zawidz: 14 alertów, PHP/5.6.5 (high risk, low confidence – pilna weryfikacja); 199 kandydatów CVE, częściowy fingerprinting i nieudana kontrola danych certyfikatu TLS. Ograniczenia muszą być widoczne już na pierwszej stronie. Nie określaj całej domeny jako podatnej.

Wymagane rezultaty: działający kod, zaadaptowany katalog YAML, jeden PDF na skan, testy, opis zmienionych plików i uruchomienia. W odpowiedzi końcowej wskaż, jakie założenia przyjąłeś, jakie testy faktycznie uruchomiłeś, czego nie udało się potwierdzić i czy wejściowy JSON zawiera wszystko, co potrzebne. Nie twierdź, że przeanalizowałeś dane, których nie otrzymałeś. Nie wysyłaj raportów. Zakończ po implementacji, nie tylko po opisaniu projektu.
