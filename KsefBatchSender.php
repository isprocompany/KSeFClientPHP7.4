<?php

/**
Klasę wrzucam do wsadowego wysyłania faktur, ale jest dość skomplikowana, ponieważ działa w warunkach konkretnej bazy danych, 
przypisanej do określonych tabel. 
Na tym etapie testuję jeszcze różne rozwiązania, dlatego traktuję to raczej jako ciekawostkę i wstępny plan działania na przyszłość, 
jeśli chodzi o metodę wsadową.
Głównym założeniem jest to, że klasa opiera się na bazie danych i tabelach systemowych, w 
których znajduje się informacja o niewysłaniu faktury do KSeF (pole typu bool) oraz wersja dokumentu FA(3). 
Po spełnieniu warunków klasa wykonuje wysyłkę.
Do dalszej pracy potrzebne są jednak tabele z danymi do API oraz po stronie wysyłającej.
Innymi słowy – trudno to obecnie przerobić na w pełni uniwersalny kod gotowy do użycia, 
ale będę stopniowo dążył do jego uporządkowania i unifikacji.
Oczywiście osoby kumające bez problemu przepiszą sobie pod swoje środowisko…
Przykładowy Cron:
59 23 * * * /usr/bin/php /var/www/html/nazwa_skryptu.php >> /var/www/html/logs/cron_log.txt 2>&1
*/


class KsefBatchSender
{
    private \PDO $pdo;
    private string $masterKey;

    private string $apiUrl;              // address z ksef_addres_api (np. https://ksef-test.mf.gov.pl)
    private string $nip;                 // nip z ksef_addres_api
    private bool  $saveZipDebug = false; // domyślnie: nie zapisuje ZIP

    /** PEM z publicznym certyfikatem MF (pobrany z endpointa) */
    private string $mfPublicKeyPem = '';

    /** Twój certyfikat/klucz z pola Certyfikat (jakby był potrzebny do podpisu itp.) */
    private ?string $clientCertPem = null;

    /** Token/hasło z pola token (hasło do certu, NIE Bearer) */
    private ?string $certPassword = null;

    /** BearerPayload sesji KSeF – przekazywany z zewnątrz do konstruktora */
    private string $sessionToken;

    /**
     * @param string $sessionToken BearerPayload zwrócony przez KSeF po InitSession
     */
    public function __construct(string $sessionToken)
    {
        if (trim($sessionToken) === '') {
            throw new \RuntimeException('Pusty sessionToken w konstruktorze KsefBatchSender.');
        }
        $this->sessionToken = trim($sessionToken);

        require __DIR__ . '/config_db.php';
        // spodziewane zmienne: $remoteDsn, $remoteUsername, $remotePassword, $ksefMasterKey

        if (empty($remoteDsn) || empty($remoteUsername)) {
            throw new \RuntimeException('Brak poprawnej konfiguracji bazy w config_db.php');
        }
        if (empty($ksefMasterKey)) {
            throw new \RuntimeException('Brak zdefiniowanego $ksefMasterKey (KSEF_MASTER_KEY).');
        }

        $this->masterKey = $ksefMasterKey;

        $this->pdo = new \PDO(
            $remoteDsn,
            $remoteUsername,
            $remotePassword,
            [
                \PDO::ATTR_ERRMODE            => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            ]
        );

        $this->loadActiveConfig();
    }

    public function enableZipDebug(bool $enabled = true): void
    {
        $this->saveZipDebug = $enabled;
    }

    /**
     * Główna procedura:
     *  - wybiera faktury z baza_fv,
     *  - pakuje je do ZIP,
     *  - szyfruje ZIP,
     *  - otwiera sesję wsadową /v2/sessions/batch,
     *  - wysyła zaszyfrowany ZIP na storage (PUT),
     *  - oznacza faktury jako wysłane.
     *
     * Zwraca:
     *  - referenceNumber (string), jeśli wsad został utworzony i wysłany,
     *  - null, jeśli nie było faktur do wysyłki.
     */
    public function sendBatch(int $maxAgeHours = 48, int $limit = 100): ?string
    {
        $invoices = $this->loadBatchCandidates($maxAgeHours, $limit);

        if (empty($invoices)) {
            echo "Brak faktur do wysyłki wsadowej.\n";
            return null;
        }

        $fileMap  = [];
        $zipPlain = $this->buildZipFromInvoices($invoices, $fileMap);

        // jeśli debug ZIP-ów jest włączony – zapisz paczkę do wsady/
        if ($this->saveZipDebug) {
            $zipDir     = $this->ensureZipDebugDir();
            $tmpZipPath = $zipDir . '/ksef_batch_' . date('Ymd_His') . '.zip';
            file_put_contents($tmpZipPath, $zipPlain);
            echo "📦 Utworzono lokalną kopię ZIP wsadu: {$tmpZipPath}\n";
        }

        // ile faktycznie trafiło do ZIP-a (mogą odpaść te z pustym XML itp.)
        $sentCount = count($fileMap);

        if ($sentCount === 0) {
            echo "Brak poprawnych faktur (XML) do umieszczenia w paczce wsadowej.\n";
            return null;
        }

        // szyfrowanie ZIP-a
        $enc          = $this->encryptZipForKsef($zipPlain);
        $encryptedZip = $enc['encryptedZip'];

        $payload = [
            "formCode" => [
                "systemCode"    => "FA (3)",
                "schemaVersion" => "1-0E",
                "value"         => "FA"
            ],
            "batchFile" => [
                "fileSize" => $enc['plainSize'],
                "fileHash" => $enc['plainHash'],
                "fileParts" => [
                    [
                        "ordinalNumber" => 1,
                        "fileSize"      => $enc['encryptedSize'],
                        "fileHash"      => $enc['encryptedHash'],
                    ]
                ]
            ],
            "encryption" => [
                "encryptedSymmetricKey" => $enc['encryptedSymmetricKey'],
                "initializationVector"  => $enc['initializationVector'],
            ],
            "offlineMode" => false
        ];

        // KROK 1: /v2/sessions/batch – otwieramy sesję wsadową
        $response = $this->callBatchSessionEndpoint($payload);

        // numer wsadu + dane do uploadu
        $batchRef           = $response['referenceNumber'] ?? $response['batchReference'] ?? null;
        $partUploadRequests = $response['partUploadRequests'] ?? [];

        if (!$batchRef) {
            throw new \RuntimeException(
                'Brak numeru referencyjnego wsadu w odpowiedzi z KSeF: ' .
                json_encode($response, JSON_UNESCAPED_UNICODE)
            );
        }

        if (empty($partUploadRequests)) {
            throw new \RuntimeException(
                'Brak partUploadRequests w odpowiedzi z KSeF – nie mam gdzie wysłać zaszyfrowanego ZIP-a: ' .
                json_encode($response, JSON_UNESCAPED_UNICODE)
            );
        }

        // KROK 2: upload zaszyfrowanego ZIP-a na storage (PUT)
        $this->uploadBatchParts($partUploadRequests, $encryptedZip);

        // dopiero po udanym uploadzie oznaczamy faktury jako wysłane
        foreach ($invoices as $fv) {
            $numer = $fv['numer'];
            try {
                $this->markAsSent($numer, $batchRef, null);
            } catch (\Throwable $e) {
                $this->markAsError($numer, 'Błąd aktualizacji po wsadzie: ' . $e->getMessage());
            }
        }

        // ładny, pełny wypis na CLI
              echo "Wysłano wsad do KSeF:\n";
        echo "  Reference: {$batchRef}\n";
        echo "  Liczba faktur w paczce: {$sentCount}\n";

        echo "  Części do uploadu:\n";
        foreach ($partUploadRequests as $part) {
            $ord    = $part['ordinalNumber'] ?? '?';
            $method = $part['method']        ?? 'PUT';
            $url    = $part['url']           ?? '(brak URL)';

            echo "    - Część {$ord}\n";
            echo "      Metoda: {$method}\n";
            echo "      URL: {$url}\n";

            if (!empty($part['headers']) && is_array($part['headers'])) {
                echo "      Nagłówki:\n";
                foreach ($part['headers'] as $hk => $hv) {
                    echo "        {$hk}: {$hv}\n";
                }
            }
        }

        echo "Pełna odpowiedź KSeF:\n";
        echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";

        // 👇 NOWE – zwracamy numer wsadu, żeby można było od razu pytać o status
        return $batchRef;
    }

/**
 * Pobiera informacje o konkretnej sesji wsadowej przez /api/v2/sessions
 * (typ Batch + filtr po referenceNumber) i ładnie wypisuje.
 */
public function showBatchSessionFromList(string $referenceNumber): void
{
    $referenceNumber = trim($referenceNumber);
    if ($referenceNumber === '') {
        throw new \RuntimeException('showBatchSessionFromList: pusty referenceNumber.');
    }

    $result = $this->callSessionsListEndpoint([
        'sessionType'     => 'Batch',
        'referenceNumber' => $referenceNumber,
        'pageSize'        => 10,
    ]);

    $sessions = $result['sessions'] ?? [];

    echo "Lista sesji (Batch) dla referenceNumber={$referenceNumber}:\n";

    if (empty($sessions)) {
        echo "  Brak sesji spełniających kryteria.\n";
        echo "Pełna odpowiedź /v2/sessions:\n";
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
        return;
    }

    $s = $sessions[0];

    $statusCode = $s['status']['code']        ?? null;
    $statusDesc = $s['status']['description'] ?? '';
    $dateCreated = $s['dateCreated'] ?? '';
    $dateUpdated = $s['dateUpdated'] ?? '';
    $total       = $s['totalInvoiceCount']      ?? null;
    $ok          = $s['successfulInvoiceCount'] ?? null;
    $failed      = $s['failedInvoiceCount']     ?? null;

    echo "  Status sesji: {$statusCode} - {$statusDesc}\n";
    echo "  Utworzona:    {$dateCreated}\n";
    echo "  Zaktualizowana: {$dateUpdated}\n";
    echo "  Faktury (łącznie / OK / błędne): {$total} / {$ok} / {$failed}\n";

    echo "Pełna odpowiedź /v2/sessions:\n";
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
}


    /**
 * GET /api/v2/sessions
 * Zwraca listę sesji wg kryteriów (tu: typ Batch, filtr po referenceNumber).
 */
private function callSessionsListEndpoint(array $query): array
{
    $url = $this->buildApiUrl('/v2/sessions');

    if (!empty($query)) {
        $url .= '?' . http_build_query($query);
    }

    $ch = curl_init($url);

    $headers = [
        'Accept: application/json',
        'Authorization: Bearer ' . $this->sessionToken,
    ];

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $headers,
    ]);

    $respBody = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err      = curl_error($ch);

    curl_close($ch);

    if ($respBody === false) {
        throw new \RuntimeException('Błąd cURL przy /v2/sessions: ' . $err);
    }

    if ($httpCode < 200 || $httpCode >= 300) {
        throw new \RuntimeException(
            'KSeF HTTP ' . $httpCode . ' przy /v2/sessions: ' . $respBody
        );
    }

    $data = json_decode($respBody, true);
    if (!is_array($data)) {
        throw new \RuntimeException('Niepoprawny JSON z /v2/sessions: ' . $respBody);
    }

    return $data;
}


    /**
     * Wysyła zaszyfrowany ZIP (encryptedZip) na URL-e z partUploadRequests.
     */
    private function uploadBatchParts(array $partUploadRequests, string $encryptedZip): void
    {
        foreach ($partUploadRequests as $part) {
            $url = $part['url'] ?? null;
            if (!$url) {
                continue;
            }

            $method = strtoupper($part['method'] ?? 'PUT');
            if ($method !== 'PUT') {
                $method = 'PUT';
            }

            $headersArr = [];
            $hdrs       = $part['headers'] ?? [];
            if (is_array($hdrs)) {
                foreach ($hdrs as $k => $v) {
                    $headersArr[] = $k . ': ' . $v;
                }
            }

            // dla pewności dodajemy Content-Length
            $headersArr[] = 'Content-Length: ' . strlen($encryptedZip);

            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER     => $headersArr,
                CURLOPT_POSTFIELDS     => $encryptedZip,
            ]);

            $respBody = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err      = curl_error($ch);

            curl_close($ch);

            if ($respBody === false) {
                throw new \RuntimeException('Błąd cURL przy uploadzie ZIP-a do storage: ' . $err);
            }

            if ($httpCode < 200 || $httpCode >= 300) {
                throw new \RuntimeException(
                    'Błąd uploadu ZIP-a do storage (HTTP ' . $httpCode . '): ' . $respBody
                );
            }
        }

        echo "  ✅ Zaszyfrowany ZIP został poprawnie wysłany do storage KSeF.\n";
    }

    /**
     * Tworzy katalog na ZIP-y (wsady/) i zabezpiecza go przed dostępem HTTP
     * oraz wykonywaniem skryptów (dla Apache).
     *
     * Zwraca pełną ścieżkę katalogu.
     */
    private function ensureZipDebugDir(): string
    {
        $dir = __DIR__ . '/wsady';

        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }

        // .htaccess – blokada listowania, dostępu i wykonywania skryptów
        $htaccessPath = $dir . '/.htaccess';
        if (!file_exists($htaccessPath)) {
            $ht = <<<'HT'
Options -Indexes

<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
    Deny from all
</IfModule>

# dodatkowa blokada wykonywania potencjalnych skryptów
<FilesMatch "\.(php|phar|phtml|pl|py|jsp|sh|cgi)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Deny from all
    </IfModule>
</FilesMatch>
HT;
            file_put_contents($htaccessPath, $ht);
        }

        // prosty index.html – żeby nawet przy padniętym .htaccess nie było listowania
        $indexPath = $dir . '/index.html';
        if (!file_exists($indexPath)) {
            file_put_contents($indexPath, "Access denied.");
        }

        return $dir;
    }

    /* ======================= KONFIG Z BAZY ======================= */

    private function loadActiveConfig(): void
    {
        $stmt = $this->pdo->query("SELECT * FROM ksef_addres_api WHERE selected = 1 LIMIT 1");
        $row  = $stmt->fetch();

        if (!$row) {
            throw new \RuntimeException('Brak aktywnej konfiguracji KSeF (ksef_addres_api.selected = 1).');
        }

        $this->apiUrl = rtrim(trim((string)$row['address']), '/'); // np. https://ksef-test.mf.gov.pl
        $this->nip    = trim((string)$row['nip']);

        if ($this->apiUrl === '') {
            throw new \RuntimeException('Puste address w ksef_addres_api (selected = 1).');
        }
        if ($this->nip === '') {
            throw new \RuntimeException('Pusty nip w ksef_addres_api (selected = 1).');
        }

        $encryptedCert  = $row['Certyfikat'] ?? null;
        $encryptedToken = $row['token']      ?? null;

        $this->clientCertPem = $this->decryptField($encryptedCert);
        $this->certPassword  = $this->decryptField($encryptedToken);
    }

    private function decryptField(?string $ciphertextB64): ?string
    {
        if ($ciphertextB64 === null || $ciphertextB64 === '') {
            return null;
        }

        $data = base64_decode($ciphertextB64, true);
        if ($data === false || strlen($data) < 32) {
            return null;
        }

        $salt       = substr($data, 0, 16);
        $iv         = substr($data, 16, 16);
        $ciphertext = substr($data, 32);

        $key = hash('sha256', $this->masterKey . $salt, true);

        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        return $plaintext === false ? null : $plaintext;
    }

    /* =================== POMOCNICZY URL DO API =================== */

    private function buildApiUrl(string $path): string
    {
        $base = rtrim($this->apiUrl, '/');

        if (!preg_match('#/api$#', $base)) {
            $base .= '/api';
        }

        return $base . $path;
    }

    /* ================== WYBÓR FAKTUR DO WSADU ==================== */

    public function loadBatchCandidates(int $maxAgeHours = 48, int $limit = 100): array
    {
        $limit = max(1, $limit);

        $minTs   = time() - ($maxAgeHours * 3600);
        $minDate = date('Y-m-d', $minTs);

        $sql = "
            SELECT *
            FROM baza_fv
            WHERE wersja_FA = 'FA(3)'
              AND (czy_zgloszono_do_ksef IS NULL OR czy_zgloszono_do_ksef = 0)
              AND (Identification_number_of_invoice_in_KseF IS NULL
                   OR Identification_number_of_invoice_in_KseF = '')
              AND (ksefReferenceNumber IS NULL
                   OR ksefReferenceNumber = '')
              AND STR_TO_DATE(data_wystawienia, '%Y-%m-%d') >= STR_TO_DATE(:minDate, '%Y-%m-%d')
            ORDER BY data_wystawienia DESC, numer ASC
            LIMIT {$limit}
        ";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':minDate' => $minDate]);

        return $stmt->fetchAll();
    }

    /* ============== OZNACZANIE SUKCESU / BŁĘDU =================== */

    public function markAsSent(string $numer, ?string $ksefReferenceNumber = null, ?string $ksefInvoiceId = null): void
    {
        $numer = trim($numer);
        if ($numer === '') {
            throw new \RuntimeException('markAsSent: pusty numer faktury.');
        }

        $fields = [];
        $params = [
            ':numer' => $numer,
            ':now'   => date('Y-m-d H:i:s'),
        ];

        $fields[] = 'czy_zgloszono_do_ksef = 1';
        $fields[] = 'data_zgloszneia_do_ksef = :now';

        if ($ksefReferenceNumber !== null && trim($ksefReferenceNumber) !== '') {
            $fields[]       = 'ksefReferenceNumber = :ref';
            $params[':ref'] = trim($ksefReferenceNumber);
        }

        if ($ksefInvoiceId !== null && trim($ksefInvoiceId) !== '') {
            $fields[]         = 'Identification_number_of_invoice_in_KseF = :invId';
            $params[':invId'] = trim($ksefInvoiceId);
        }

        $sql = 'UPDATE baza_fv SET ' . implode(', ', $fields) . ' WHERE numer = :numer';

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        if ($stmt->rowCount() === 0) {
            throw new \RuntimeException('markAsSent: nie znaleziono faktury o numerze ' . $numer);
        }
    }
	
    public function markAsError(string $numer, string $errorMessage): void
    {
        $numer        = trim($numer);
        $errorMessage = trim($errorMessage);

        if ($numer === '') {
            throw new \RuntimeException('markAsError: pusty numer.');
        }
        if ($errorMessage === '') {
            throw new \RuntimeException('markAsError: pusty komunikat błędu.');
        }

        $sql = "
            UPDATE baza_fv
            SET
                czy_zgloszono_do_ksef = 0,
                ksef_error_message    = :msg
            WHERE numer = :numer
        ";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':msg'   => $errorMessage,
            ':numer' => $numer,
        ]);

        if ($stmt->rowCount() === 0) {
            throw new \RuntimeException('markAsError: nie znaleziono faktury o numerze ' . $numer);
        }
    }
	
        /**
     * Pobiera plik UPO (XML) z podanego URL i zapisuje go w kolumnie xml_Content
     * w tabeli baza_fv dla wskazanej faktury (po polu numer).
     */

	public function downloadAndStoreInvoiceUpo(string $invoiceNumber, string $upoUrl): void
{
    $invoiceNumber = trim($invoiceNumber);
    $upoUrl        = trim($upoUrl);

    if ($invoiceNumber === '') {
        throw new \RuntimeException('downloadAndStoreInvoiceUpo: pusty numer faktury.');
    }
    if ($upoUrl === '') {
        throw new \RuntimeException('downloadAndStoreInvoiceUpo: pusty URL UPO.');
    }

    // ⚠️ UWAGA: to jest SAS URL, NIE dodajemy Authorization!
    $ch = curl_init($upoUrl);
    if ($ch === false) {
        throw new \RuntimeException('curl_init() zwrócił false przy pobieraniu UPO.');
    }

    $headers = [
        'Accept: application/xml, application/octet-stream, */*',
    ];

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => 60,
        CURLOPT_HTTPHEADER     => $headers,
    ]);

    $body     = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err      = curl_error($ch);

    curl_close($ch);

    if ($body === false) {
        throw new \RuntimeException('Błąd cURL przy pobieraniu UPO: ' . $err);
    }
    if ($httpCode !== 200) {
        throw new \RuntimeException('HTTP ' . $httpCode . ' przy pobieraniu UPO: ' . substr($body, 0, 1000));
    }

    $upoXml = trim($body);
    if ($upoXml === '') {
        throw new \RuntimeException('downloadAndStoreInvoiceUpo: puste UPO XML.');
    }

    // zapis do baza_fv.xml_Content
    $sql = "UPDATE baza_fv SET xml_Content = :xml WHERE numer = :numer";

    $stmt = $this->pdo->prepare($sql);
    $stmt->execute([
        ':xml'   => $upoXml,
        ':numer' => $invoiceNumber,
    ]);

    if ($stmt->rowCount() === 0) {
        throw new \RuntimeException(
            'downloadAndStoreInvoiceUpo: nie znaleziono faktury o numerze ' . $invoiceNumber
        );
    }

    echo "    ✅ UPO zostało pobrane i zapisane w xml_Content dla faktury {$invoiceNumber}.\n";
}


    /* ================= STATUS + SUBMIT ================= */

    /**
     * Sprawdza status sesji/wsadu w KSeF na podstawie referenceNumber
     * i wypisuje pełną odpowiedź JSON.
     */

    public function processBatchStatus(string $referenceNumber): int
{
    $referenceNumber = trim($referenceNumber);
    if ($referenceNumber === '') {
        throw new \RuntimeException('processBatchStatus: pusty referenceNumber.');
    }

    $status = $this->callSessionStatusEndpoint($referenceNumber);

    echo "Status sesji/wsadu w KSeF dla referenceNumber: {$referenceNumber}\n";

    $code        = $status['status']['code']        ?? null;
    $description = $status['status']['description'] ?? '';
    $validUntil  = $status['validUntil']            ?? '';

    // 🧭 mapa statusów z dokumentacji KSeF
    $statusMap = [
        100 => 'Sesja wsadowa rozpoczęta',
        150 => 'Trwa przetwarzanie',
        200 => 'Sesja wsadowa przetworzona pomyślnie',
        405 => 'Błąd weryfikacji poprawności elementów paczki',
        415 => 'Błąd odszyfrowania dostarczonego klucza',
        420 => 'Przekroczony limit faktur w sesji',
        430 => 'Błąd dekompresji pierwotnego archiwum',
        435 => 'Błąd odszyfrowania zaszyfrowanych części archiwum',
        440 => 'Sesja anulowana (czas lub brak faktur)',
        445 => 'Błąd weryfikacji, brak poprawnych faktur',
        500 => 'Nieznany błąd (statusCode)',
    ];

    $extra = $statusMap[$code] ?? '(nieznany kod statusu)';

    echo "  Kod statusu: {$code}\n";
    echo "  Opis systemowy: {$description}\n";
    echo "  Znaczenie: {$extra}\n";

    if ($validUntil !== '') {
        echo "  Ważna do: {$validUntil}\n";
    }

    echo "Pełna odpowiedź KSeF (ksefSessionStatus):\n";
    echo json_encode($status, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";

    // 🔙 ważne: zwracamy kod, żeby wsad.php mógł go używać
    return (int)($code ?? 0);
}


    /**
     * Zgłasza wsad do przetwarzania (submitBatch)
     */
    public function submitBatch(string $referenceNumber): void
    {
        $referenceNumber = trim($referenceNumber);
        if ($referenceNumber === '') {
            throw new \RuntimeException('submitBatch: pusty referenceNumber.');
        }

        $resp = $this->callBatchSubmitEndpoint($referenceNumber);

        echo "Wywołano submitBatch dla referenceNumber: {$referenceNumber}\n";
        echo "Odpowiedź KSeF (submitBatch):\n";
        echo json_encode($resp, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
    }

        /**
     * GET /api/v2/sessions/{referenceNumber}/invoices
     * Zwraca listę faktur w danej sesji (w tym wsadowej).
     */
    private function callSessionInvoicesEndpoint(
        string $referenceNumber,
        ?string $continuationToken = null,
        int $pageSize = 100
    ): array {
        $referenceNumber = trim($referenceNumber);
        if ($referenceNumber === '') {
            throw new \RuntimeException('callSessionInvoicesEndpoint: pusty referenceNumber.');
        }

        // wg innych endpointów – pageSize między 10 a 500
        $pageSize = max(10, min(500, $pageSize));

        $query = [
            'pageSize'      => $pageSize,
        ];
        if ($continuationToken !== null) {
            $query['continuationToken'] = $continuationToken;
        }

        $url = $this->buildApiUrl(
            '/v2/sessions/' . rawurlencode($referenceNumber) . '/invoices'
        );
        if (!empty($query)) {
            $url .= '?' . http_build_query($query);
        }

        $ch = curl_init($url);

        $headers = [
            'Accept: application/json',
            'Authorization: Bearer ' . $this->sessionToken,
        ];

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
        ]);

        $respBody = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err      = curl_error($ch);

        curl_close($ch);

        if ($respBody === false) {
            throw new \RuntimeException('Błąd cURL przy /v2/sessions/{referenceNumber}/invoices: ' . $err);
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            throw new \RuntimeException(
                'KSeF HTTP ' . $httpCode . ' przy /v2/sessions/{referenceNumber}/invoices: ' . $respBody
            );
        }

        $data = json_decode($respBody, true);
        if (!is_array($data)) {
            throw new \RuntimeException('Niepoprawny JSON z /v2/sessions/{referenceNumber}/invoices: ' . $respBody);
        }

        return $data;
    }

    /**
     * Pobiera wszystkie faktury z danej sesji wsadowej (GET /sessions/{ref}/invoices),
     * wypisuje ich statusy i (opcjonalnie) aktualizuje tabelę baza_fv.
     *
     * Założenie: invoiceNumber z KSeF = numer z Twojej kolumny 'numer' w baza_fv.
     */

	function processBatchInvoices(string $referenceNumber, bool $updateDb = true, bool $downloadUpoToDb = false): void
    {
        $referenceNumber = trim($referenceNumber);
        if ($referenceNumber === '') {
            throw new \RuntimeException('processBatchInvoices: pusty referenceNumber.');
        }

        echo "Faktury w sesji wsadowej (referenceNumber: {$referenceNumber}):\n";

        $allInvoices        = [];
        $continuationToken  = null;

        do {
            $page = $this->callSessionInvoicesEndpoint($referenceNumber, $continuationToken, 100);

            $invoicesPage = $page['invoices'] ?? [];
            if (!empty($invoicesPage)) {
                foreach ($invoicesPage as $inv) {
                    $allInvoices[] = $inv;
                }
            }

            $continuationToken = $page['continuationToken'] ?? null;
        } while (!empty($continuationToken));

        if (empty($allInvoices)) {
            echo "  Brak faktur w tej sesji (KSeF zwrócił pustą listę invoices).\n";
            return;
        }

        $invoiceStatusMap = [
            200 => 'Sukces (faktura przyjęta)',
            440 => 'Duplikat faktury',
        ];

        foreach ($allInvoices as $inv) {
            $ord          = $inv['ordinalNumber'] ?? null;
            $invoiceNo    = $inv['invoiceNumber'] ?? '(brak numeru faktury)';
            $ksefNumber   = $inv['ksefNumber']    ?? null;
            $ref          = $inv['referenceNumber'] ?? null;
            $statusCode   = $inv['status']['code']        ?? null;
            $statusDesc   = $inv['status']['description'] ?? '';
            $statusDetails= $inv['status']['details']     ?? [];
            $upoUrl       = $inv['upoDownloadUrl']        ?? null;

            $humanStatus = $invoiceStatusMap[$statusCode] ?? '(nieznany kod statusu faktury)';

            echo "  - Ordinal: {$ord}\n";
            echo "    Numer faktury: {$invoiceNo}\n";
            if ($ksefNumber) {
                echo "    Numer KSeF:   {$ksefNumber}\n";
            }
            if ($ref) {
                echo "    Reference:    {$ref}\n";
            }
            echo "    Status:       {$statusCode} - {$statusDesc}\n";
            echo "    Znaczenie:    {$humanStatus}\n";

            if (!empty($statusDetails) && is_array($statusDetails)) {
                echo "    Szczegóły:\n";
                foreach ($statusDetails as $d) {
                    echo "      * {$d}\n";
                }
            }

            if ($upoUrl) {
                echo "    UPO URL:      {$upoUrl}\n";
                $exp = $inv['upoDownloadUrlExpirationDate'] ?? null;
                if ($exp) {
                    echo "    UPO ważne do: {$exp}\n";
                }

                if ($downloadUpoToDb && $invoiceNo !== '(brak numeru faktury)') {
                    try {
                        $this->downloadAndStoreInvoiceUpo($invoiceNo, $upoUrl);
                    } catch (\Throwable $e) {
                        echo "    ⚠️ Błąd pobierania/zapisu UPO dla faktury {$invoiceNo}: "
                             . $e->getMessage() . "\n";
                    }
                }
            }

            echo "\n";

            // opcjonalna aktualizacja bazy (baza_fv)
            if ($updateDb && $invoiceNo !== '(brak numeru faktury)') {
                try {
                    // zakładamy, że invoiceNumber = baza_fv.numer
                    if ($statusCode === 200 && $ksefNumber) {
                        // faktura przyjęta
                        $this->markAsSent($invoiceNo, $referenceNumber, $ksefNumber);
                    } elseif ($statusCode !== null && $statusCode >= 400) {
                        // błąd / duplikat / itp.
                        $msg = "KSeF invoice status {$statusCode}: {$statusDesc}";
                        if (!empty($statusDetails[0])) {
                            $msg .= ' | ' . $statusDetails[0];
                        }
                        $this->markAsError($invoiceNo, $msg);
                    }
                } catch (\Throwable $e) {
                    echo "    ⚠️ Błąd aktualizacji bazy dla faktury {$invoiceNo}: " .
                         $e->getMessage() . "\n";
                }
            }
        }

        echo "Pełna lista faktur (JSON z /invoices):\n";
        echo json_encode($allInvoices, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
    }

    /**
     * POST /api/v2/sessions/batch/{referenceNumber}/close
     * Zamyka sesję wsadową – informuje KSeF, że wszystkie pliki zostały przesłane.
     */
        /**
     * POST /api/v2/sessions/batch/{referenceNumber}/close
     * Zamyka sesję wsadową – informuje KSeF, że wszystkie pliki zostały przesłane.
     */
    public function closeBatch(string $referenceNumber): array
    {
        $referenceNumber = trim($referenceNumber);
        if ($referenceNumber === '') {
            throw new \RuntimeException('closeBatch: pusty referenceNumber.');
        }

        $url = $this->buildApiUrl(
            '/v2/sessions/batch/' . rawurlencode($referenceNumber) . '/close'
        );

        $ch = curl_init($url);
        $headers = [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $this->sessionToken,
        ];

        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_POSTFIELDS     => '{}',   // zwykle pusty JSON
        ]);

        $respBody = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err      = curl_error($ch);

        curl_close($ch);

        if ($respBody === false) {
            throw new \RuntimeException('Błąd cURL przy closeBatch: ' . $err);
        }

        // 2xx = sukces, ale czasem 204 / pusty body
        if ($httpCode < 200 || $httpCode >= 300) {
            throw new \RuntimeException(
                'KSeF HTTP ' . $httpCode . ' przy closeBatch: ' . $respBody
            );
        }

        // jeśli brak treści albo tylko whitespace – uznaj za sukces bez danych
        if (trim($respBody) === '') {
            echo "✅ Sesja wsadowa została zamknięta (/close zwróciło kod {$httpCode} bez treści).\n";
            return [
                'httpCode' => $httpCode,
                'body'     => null,
            ];
        }

        $data = json_decode($respBody, true);
        if (!is_array($data)) {
            // zamiast rzucać wyjątek – pokaż surową odpowiedź i i tak traktuj jako sukces
            echo "ℹ️  /close zwróciło nie-JSON, ale kod HTTP {$httpCode}. Surowa odpowiedź:\n";
            echo $respBody . "\n";

            return [
                'httpCode' => $httpCode,
                'body'     => $respBody,
            ];
        }

        echo "✅ Sesja wsadowa została zamknięta (HTTP {$httpCode}).\n";
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";

        return $data;
    }
    
    // w KsefBatchSender.php, np. zaraz pod processBatchInvoices()

/**
 * Wrapper wygodny do użycia w skryptach CLI:
 * wypisuje faktury z sesji wsadowej, opcjonalnie aktualizuje bazę.
 */
public function listBatchInvoices(string $referenceNumber, bool $updateDb = true): void
{
    $this->processBatchInvoices($referenceNumber, $updateDb);
}


    /**
     * GET /api/v2/sessions/{referenceNumber}
     * Zwraca status sesji (online/wsadowej).
     */
    private function callSessionStatusEndpoint(string $referenceNumber): array
    {
        $url = $this->buildApiUrl('/v2/sessions/' . rawurlencode($referenceNumber));

        $ch = curl_init($url);

        $headers = [
            'Accept: application/json',
            'Authorization: Bearer ' . $this->sessionToken,
        ];

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
        ]);

        $respBody = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err      = curl_error($ch);

        curl_close($ch);

        if ($respBody === false) {
            throw new \RuntimeException('Błąd cURL przy /v2/sessions/{referenceNumber}: ' . $err);
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            throw new \RuntimeException(
                'KSeF HTTP ' . $httpCode . ' przy /v2/sessions/{referenceNumber}: ' . $respBody
            );
        }

        $data = json_decode($respBody, true);
        if (!is_array($data)) {
            throw new \RuntimeException('Niepoprawny JSON z /v2/sessions/{referenceNumber}: ' . $respBody);
        }

        return $data;
    }

    /**
     * POST /api/v2/sessions/batch/{referenceNumber}/submit
     * Zgłoszenie wsadu do przetwarzania.
     */
    private function callBatchSubmitEndpoint(string $referenceNumber): array
    {
        $url = $this->buildApiUrl(
            '/v2/sessions/batch/' . rawurlencode($referenceNumber) . '/submit'
        );

        $ch = curl_init($url);

        $headers = [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $this->sessionToken,
        ];

        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_POSTFIELDS     => '{}',
        ]);

        $respBody = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err      = curl_error($ch);

        curl_close($ch);

        if ($respBody === false) {
            throw new \RuntimeException('Błąd cURL przy submitBatch: ' . $err);
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            throw new \RuntimeException(
                'KSeF HTTP ' . $httpCode . ' przy submitBatch: ' . $respBody
            );
        }

        $data = json_decode($respBody, true);
        if (!is_array($data)) {
            throw new \RuntimeException('Niepoprawny JSON z submitBatch: ' . $respBody);
        }

        return $data;
    }

    /* ======================= ZIP z faktur ======================== */

    private function buildZipFromInvoices(array $invoices, array &$fileMap): string
    {
        $fileMap = [];

        $tmp = tmpfile();
        if ($tmp === false) {
            throw new \RuntimeException('Nie udało się stworzyć pliku tymczasowego ZIP.');
        }

        $meta = stream_get_meta_data($tmp);
        $path = $meta['uri'];

        $zip = new \ZipArchive();
        if ($zip->open($path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
            fclose($tmp);
            throw new \RuntimeException('Nie udało się otworzyć ZIP.');
        }

        foreach ($invoices as $fv) {
            $numer = $fv['numer'];

            $safeName = preg_replace('/[^A-Za-z0-9_\-]/', '_', $numer) . '.xml';
            $xml      = $fv['xml_Content'] ?? $fv['xml_file'] ?? '';

            if (trim($xml) === '') {
                $this->markAsError($numer, 'Brak XML (xml_Content/xml_file) – pomijam w paczce.');
                continue;
            }

            if ($zip->addFromString($safeName, $xml) === false) {
                $this->markAsError($numer, 'Nie udało się dodać pliku do ZIP.');
                continue;
            }

            $fileMap[$numer] = $safeName;
        }

        $zip->close();

        $zipBinary = file_get_contents($path);
        fclose($tmp);

        if ($zipBinary === false || $zipBinary === '') {
            throw new \RuntimeException('ZIP jest pusty albo nieczytelny.');
        }

        return $zipBinary;
    }

    /* ================== SZYFROWANIE ZIP + HASH =================== */


    private function encryptZipForKsef(string $zipPlain): array
{
    $this->ensureMfPublicKeyLoaded();

    // 1. losowy klucz AES i IV
    $symKey = random_bytes(32); // 256-bit
    $iv     = random_bytes(16); // 128-bit

    // 2. szyfrowanie ZIP AES-256-CBC
    $zipEncrypted = openssl_encrypt(
        $zipPlain,
        'aes-256-cbc',
        $symKey,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($zipEncrypted === false) {
        throw new \RuntimeException('Błąd szyfrowania ZIP (AES-256-CBC).');
    }

    // 3. przygotowanie plików tymczasowych
    $tmpDir       = sys_get_temp_dir();
    $tmpKeyFile   = tempnam($tmpDir, 'ksef_symkey_');
    $tmpCertFile  = tempnam($tmpDir, 'ksef_cert_');
    $tmpPubFile   = $tmpCertFile . '.pub.pem';
    $tmpEncFile   = $tmpKeyFile . '.enc';

    // klucz symetryczny -> plik
    file_put_contents($tmpKeyFile, $symKey);
    // certyfikat MF -> plik
    file_put_contents($tmpCertFile, $this->mfPublicKeyPem);

    // 4. wyciągnięcie PUBLIC KEY z certyfikatu
    $cmdExtract = sprintf(
        'openssl x509 -in %s -pubkey -noout -out %s 2>&1',
        escapeshellarg($tmpCertFile),
        escapeshellarg($tmpPubFile)
    );

    $outputExtract = [];
    $retExtract    = 0;
    exec($cmdExtract, $outputExtract, $retExtract);

    if ($retExtract !== 0 || !file_exists($tmpPubFile)) {
        $msg = "Błąd podczas ekstrakcji klucza publicznego z certyfikatu (openssl x509):\n"
             . implode("\n", $outputExtract);
        // sprzątanie
        @unlink($tmpKeyFile);
        @unlink($tmpCertFile);
        @unlink($tmpPubFile);
        @unlink($tmpEncFile);
        throw new \RuntimeException($msg);
    }

    // 5. szyfrowanie klucza symetrycznego RSA-OAEP-SHA256 + MGF1-SHA256
    $cmdEncrypt = sprintf(
        'openssl pkeyutl -encrypt -in %s -inkey %s -pubin -out %s ' .
        '-pkeyopt rsa_padding_mode:oaep ' .
        '-pkeyopt rsa_oaep_md:sha256 ' .
        '-pkeyopt rsa_mgf1_md:sha256 2>&1',
        escapeshellarg($tmpKeyFile),
        escapeshellarg($tmpPubFile),
        escapeshellarg($tmpEncFile)
    );

    $outputEncrypt = [];
    $retEncrypt    = 0;
    exec($cmdEncrypt, $outputEncrypt, $retEncrypt);

    if ($retEncrypt !== 0 || !file_exists($tmpEncFile)) {
        $msg = "Błąd podczas szyfrowania klucza RSA (openssl pkeyutl):\n"
             . implode("\n", $outputEncrypt);
        // sprzątanie
        @unlink($tmpKeyFile);
        @unlink($tmpCertFile);
        @unlink($tmpPubFile);
        @unlink($tmpEncFile);
        throw new \RuntimeException($msg);
    }

    $encryptedSymKey = file_get_contents($tmpEncFile);

    // 6. sprzątanie
    @unlink($tmpKeyFile);
    @unlink($tmpCertFile);
    @unlink($tmpPubFile);
    @unlink($tmpEncFile);

    if ($encryptedSymKey === false || strlen($encryptedSymKey) === 0) {
        throw new \RuntimeException('Nie udało się odczytać zaszyfrowanego klucza RSA.');
    }

    // 7. metadane i skróty
    $plainSize     = strlen($zipPlain);
    $encryptedSize = strlen($zipEncrypted);

    $plainHash     = base64_encode(hash('sha256', $zipPlain, true));
    $encryptedHash = base64_encode(hash('sha256', $zipEncrypted, true));

    return [
        'plainSize'             => $plainSize,
        'plainHash'             => $plainHash,
        'encryptedSize'         => $encryptedSize,
        'encryptedHash'         => $encryptedHash,
        'encryptedSymmetricKey' => base64_encode($encryptedSymKey),
        'initializationVector'  => base64_encode($iv),
        'encryptedZip'          => $zipEncrypted,
    ];
}
    


    private function ensureMfPublicKeyLoaded(): void
    {
        if (!empty($this->mfPublicKeyPem)) {
            return;
        }

        $this->mfPublicKeyPem = $this->fetchMfPublicKeyFromKsef();

        if (trim($this->mfPublicKeyPem) === '') {
            throw new \RuntimeException('Nie udało się pobrać klucza publicznego MF z KSeF.');
        }
    }

    private function fetchMfPublicKeyFromKsef(): string
{
    $url = $this->buildApiUrl('/v2/security/public-key-certificates');

    $ch = curl_init($url);

    $headers = [
        'Accept: application/json',
    ];

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $headers,
    ]);

    $respBody = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err      = curl_error($ch);

    curl_close($ch);

    if ($respBody === false) {
        throw new \RuntimeException('Błąd cURL przy pobieraniu certyfikatów z KSeF: ' . $err);
    }

    if ($httpCode < 200 || $httpCode >= 300) {
        throw new \RuntimeException(
            'KSeF HTTP ' . $httpCode . ' przy /v2/security/public-key-certificates: ' . $respBody
        );
    }

    $data = json_decode($respBody, true);
    if (!is_array($data)) {
        throw new \RuntimeException('Niepoprawny JSON z /v2/security/public-key-certificates: ' . $respBody);
    }

    $selectedCertB64 = null;

    foreach ($data as $idx => $item) {
        if (!isset($item['certificate'])) {
            continue;
        }

        $usage = $item['usage'] ?? [];
        if (!is_array($usage)) {
            $usage = [$usage];
        }

        // DEBUG: pokaż, jakie usage mają kolejne certy
        echo "DEBUG: cert #{$idx}, usage=" . implode(',', $usage) . PHP_EOL;

        if (in_array('SymmetricKeyEncryption', $usage, true)) {
            $selectedCertB64 = $item['certificate'];
            echo "DEBUG: WYBRANO cert #{$idx} (SymmetricKeyEncryption)\n";
            break;
        }
    } // <-- TUTAJ brakowało klamry w Twojej wersji

    if ($selectedCertB64 === null) {
        throw new \RuntimeException('Nie znaleziono certyfikatu MF z usage = SymmetricKeyEncryption.');
    }

    $body = chunk_split($selectedCertB64, 64, "\n");

    $pem = "-----BEGIN CERTIFICATE-----\n"
         . $body
         . "-----END CERTIFICATE-----\n";

    return $pem;
}


    /* ================= /v2/sessions/batch ======================== */

    private function callBatchSessionEndpoint(array $payload): array
    {
        $url = $this->buildApiUrl('/v2/sessions/batch');

        $ch = curl_init($url);

        $headers = [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $this->sessionToken,
        ];

        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ]);

        $respBody = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err      = curl_error($ch);

        curl_close($ch);

        if ($respBody === false) {
            throw new \RuntimeException('Błąd cURL przy /v2/sessions/batch: ' . $err);
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            throw new \RuntimeException('KSeF HTTP ' . $httpCode . ' przy /v2/sessions/batch: ' . $respBody);
        }

        $data = json_decode($respBody, true);
        if (!is_array($data)) {
            throw new \RuntimeException('Niepoprawny JSON z /v2/sessions/batch: ' . $respBody);
        }

        return $data;
    }
}

