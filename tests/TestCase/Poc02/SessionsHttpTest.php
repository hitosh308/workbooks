<?php
declare(strict_types=1);

namespace App\Test\TestCase\Poc02;

use App\Poc02\SessionKind;
use App\Poc02\Sessions;
use App\Poc02\SessionStore;
use CurlHandle;
use FilesystemIterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;

final class SessionsHttpTest extends TestCase
{
    private string $directory;
    private int $start;
    private array $servers = [];
    private array $urls = [];

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/poc02-' . bin2hex(random_bytes(8));
        mkdir($this->directory, 0700);
        $this->start = time();
        $this->clock();
        $this->mode('enabled');
        $this->serve();
    }

    protected function tearDown(): void
    {
        foreach ($this->servers as $server) {
            proc_terminate($server);
            proc_close($server);
        }
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );
        foreach ($files as $file) {
            if ($file->isDir()) {
                rmdir($file->getPathname());
            } else {
                unlink($file->getPathname());
            }
        }
        rmdir($this->directory);
    }

    public function testIndependentSessionsAndNoCookieRecovery(): void
    {
        $jar = [];
        $page = $this->request($jar);
        self::assertSame(200, $page['code']);
        self::assertSame(['__Host-poc02-csrf'], array_keys($jar));
        self::assertFileDoesNotExist($this->directory . '/sessions/guest');
        self::assertStringContainsString('no-store', implode(' ', $page['headers']));
        $this->beginAll($jar);
        self::assertCount(3, array_unique(array_intersect_key($jar, array_flip(array_map(
            static fn(SessionKind $kind): string => $kind->cookie(),
            SessionKind::cases(),
        )))));
        $this->save($jar);
        $page = $this->request($jar);
        $this->assertActive($page, ['guest', 'member', 'admin']);
        self::assertStringContainsString('回答 1 件', $page['body']);
        foreach ($jar as $value) {
            self::assertStringNotContainsString($value, $page['body']);
        }

        $withoutGuest = $jar;
        unset($withoutGuest[SessionKind::Guest->cookie()]);
        $this->assertActive($this->request($withoutGuest), ['member', 'admin']);
        $newGuest = $this->begin($withoutGuest, SessionKind::Guest);
        self::assertStringContainsString('回答 0 件', $newGuest['body']);
        self::assertNotSame($jar[SessionKind::Guest->cookie()], $withoutGuest[SessionKind::Guest->cookie()]);

        $oldMember = $jar;
        $logout = $this->post($jar, 'member', 'logout');
        self::assertStringContainsString('expires=', strtolower($this->setCookie($logout, SessionKind::Member)));
        $page = $this->request($jar);
        $this->assertActive($page, ['guest', 'admin']);
        self::assertStringContainsString('回答 1 件', $page['body']);
        $this->assertActive($this->request($oldMember), ['guest', 'admin']);
        $this->begin($jar, SessionKind::Member);
        $this->post($jar, 'admin', 'logout');
        $this->assertActive($this->request($jar), ['guest', 'member']);
    }

    public function testCookiesCannotAuthorizeAnotherKind(): void
    {
        $jar = [];
        $this->beginAll($jar);
        $swapped = $jar;
        [$swapped[SessionKind::Member->cookie()], $swapped[SessionKind::Admin->cookie()]] =
            [$jar[SessionKind::Admin->cookie()], $jar[SessionKind::Member->cookie()]];
        self::assertSame(409, $this->post($swapped, 'admin', 'revoke')['code']);
        self::assertSame(409, $this->post($swapped, 'member', 'disable')['code']);
        $this->assertActive($this->request($jar), ['guest', 'member', 'admin']);
    }

    public function testGatingAndCsrf(): void
    {
        $jar = [];
        foreach (['disabled', 'normal', 'http', 'https-off'] as $mode) {
            $this->mode($mode);
            self::assertSame(404, $this->request($jar, null, 0, ['X-Forwarded-Proto: https'])['code']);
            self::assertSame(404, $this->request($jar, ['kind' => 'member', 'operation' => 'login'])['code']);
            self::assertSame([], $jar);
        }
        $this->mode('enabled');
        $page = $this->request($jar);
        $csrf = strtolower($this->headerCookie($page, '__Host-poc02-csrf'));
        self::assertStringContainsString('path=/', $csrf);
        self::assertStringContainsString('secure', $csrf);
        self::assertStringContainsString('httponly', $csrf);
        self::assertStringContainsString('samesite=lax', $csrf);
        $request = ['kind' => 'member', 'operation' => 'login', 'subject' => 'sample-a'];
        self::assertSame(403, $this->request($jar, $request)['code']);
        self::assertSame(403, $this->request($jar, $request + ['_csrfToken' => 'invalid'])['code']);
        self::assertSame(200, $this->post($jar, 'member', 'login', ['subject' => 'sample-a'])['code']);
        $other = [];
        $this->request($other, null, 0, ['Cookie: csrfToken=wrong']);
        self::assertArrayNotHasKey(SessionKind::Member->cookie(), $other);
    }

    public static function kinds(): array
    {
        return [
            'guest' => [SessionKind::Guest, 86400, 604800],
            'member' => [SessionKind::Member, 604800, 2592000],
            'admin' => [SessionKind::Admin, 1800, 28800],
        ];
    }

    #[DataProvider('kinds')]
    public function testIdleBoundaryAndReplay(SessionKind $kind, int $idle, int $maximum): void
    {
        $jar = [];
        $this->begin($jar, $kind);
        $original = $jar;
        $this->clock($idle - 1);
        $this->assertActive($this->request($jar), [$kind->value]);
        $this->clock(2 * $idle - 1);
        $this->assertActive($this->request($jar), []);
        self::assertArrayNotHasKey($kind->cookie(), $jar);
        $this->assertActive($this->request($original), []);
    }

    #[DataProvider('kinds')]
    public function testAbsoluteBoundaryAndCookiePolicy(SessionKind $kind, int $idle, int $maximum): void
    {
        $jar = [];
        $response = $this->begin($jar, $kind);
        $cookie = strtolower($this->setCookie($response, $kind));
        foreach (['secure', 'httponly', 'samesite=lax', 'path=/'] as $flag) {
            self::assertStringContainsString($flag, $cookie);
        }
        self::assertStringNotContainsString('domain=', $cookie);
        if ($kind === SessionKind::Admin) {
            self::assertStringNotContainsString('expires=', $cookie);
            self::assertStringNotContainsString('max-age=', $cookie);
        } else {
            preg_match('/expires=([^;]+)/', $cookie, $date);
            self::assertSame($this->start + $maximum, strtotime($date[1]));
        }

        for ($elapsed = $idle - 1; $elapsed < $maximum - 1; $elapsed += $idle - 1) {
            $this->clock($elapsed);
            $this->assertActive($this->request($jar), [$kind->value]);
        }
        $this->clock($maximum - 1);
        $page = $this->request($jar);
        $this->assertActive($page, [$kind->value]);
        self::assertStringContainsString(gmdate('Y-m-d H:i:s', $this->start + $maximum), $page['body']);
        self::assertSame('', $this->setCookie($page, $kind));
        $this->clock($maximum);
        $this->assertActive($this->request($jar), []);
    }

    public static function authenticators(): array
    {
        return ['member' => [SessionKind::Member], 'admin' => [SessionKind::Admin]];
    }

    #[DataProvider('authenticators')]
    public function testRotationLogoutAndAllDeviceRevocation(SessionKind $kind): void
    {
        $jar = $second = $other = [];
        $this->begin($jar, $kind);
        $this->begin($second, $kind);
        $this->begin($other, $kind, 'sample-b');
        $name = $kind->cookie();
        $old = $jar;
        $this->begin($jar, $kind);
        self::assertNotSame($old[$name], $jar[$name]);
        $this->assertActive($this->request($old), []);

        $loggedOut = $jar;
        $this->post($jar, $kind->value, 'logout');
        $this->assertActive($this->request($loggedOut), []);
        $this->assertActive($this->request($second), [$kind->value]);

        $this->begin($jar, $kind);
        $stolen = $jar;
        $operation = $kind === SessionKind::Admin ? 'revoke' : 'disable';
        self::assertSame(200, $this->post($jar, $kind->value, $operation)['code']);
        $this->assertActive($this->request($second), []);
        $this->assertActive($this->request($stolen), []);
        $this->assertActive($this->request($other), [$kind->value]);

        $expected = $kind === SessionKind::Admin ? 200 : 403;
        self::assertSame($expected, $this->post($jar, $kind->value, 'login', ['subject' => 'sample-a'])['code']);
        if ($kind === SessionKind::Admin) {
            $this->begin($second, $kind);
            $this->post($jar, 'admin', 'disable');
            $this->assertActive($this->request($second), []);
            self::assertSame(403, $this->post($jar, 'admin', 'login', ['subject' => 'sample-a'])['code']);
            $this->assertActive($this->request($other), ['admin']);
        }
    }

    public function testSchemaResetPreservesOtherSessionsAndRejectsStaleRevision(): void
    {
        $jar = [];
        $this->beginAll($jar);
        $this->save($jar);
        $openTab = $this->request($jar);
        $revision = $this->revision($openTab);
        $this->changeGuestRecord($jar, static function (array &$learning): void {
            $learning['schema_version'] = -1;
        });
        $stale = $this->request($jar, [
            'kind' => 'guest',
            'operation' => 'answer',
            'item' => 1,
            'revision' => $revision,
            '_csrfToken' => $this->token($openTab),
        ]);
        self::assertSame(409, $stale['code']);
        self::assertStringContainsString('学習データを初期化しました', $stale['body']);
        $page = $this->request($jar);
        $this->assertActive($page, ['guest', 'member', 'admin']);
        self::assertStringContainsString('回答 0 件', $page['body']);
        self::assertStringContainsString('学習データを初期化しました', $page['body']);
        self::assertStringNotContainsString('学習データを初期化しました', $this->request($jar)['body']);
    }

    public function testTwoWorkersCannotOverwriteTheSameRevision(): void
    {
        $this->serve();
        $jar = [];
        $this->begin($jar, SessionKind::Guest);
        $tab1 = $this->request($jar);
        $tab2 = $this->request($jar, null, 1);
        $multi = curl_multi_init();
        $handles = [];
        try {
            foreach ([$tab1, $tab2] as $worker => $page) {
                $handle = $this->curl($jar, [
                    'kind' => 'guest',
                    'operation' => 'answer',
                    'item' => $worker + 1,
                    'revision' => $this->revision($page),
                    '_csrfToken' => $this->token($page),
                ], $worker);
                $handles[] = $handle;
                curl_multi_add_handle($multi, $handle);
            }
            do {
                curl_multi_exec($multi, $running);
                if ($running > 0) {
                    curl_multi_select($multi, 1);
                }
            } while ($running > 0);
            $codes = array_map(static fn($handle): int => curl_getinfo($handle, CURLINFO_RESPONSE_CODE), $handles);
            sort($codes);
            self::assertSame([200, 409], $codes);
        } finally {
            foreach ($handles as $handle) {
                curl_multi_remove_handle($multi, $handle);
            }
        }
        $page = $this->request($jar);
        self::assertStringContainsString('回答 1 件', $page['body']);
        self::assertSame('1', $this->revision($page));
    }

    public function testExpiredAndLoggedOutGuestCannotBeRestoredByAnUpdate(): void
    {
        $jar = [];
        foreach (['expiration', 'logout'] as $reason) {
            $this->begin($jar, SessionKind::Guest);
            $page = $this->request($jar);
            $stale = $jar;
            if ($reason === 'expiration') {
                $this->clock(86400);
            } else {
                $this->post($jar, 'guest', 'logout');
            }
            $response = $this->request($stale, [
                'kind' => 'guest',
                'operation' => 'answer',
                'item' => 1,
                'revision' => $this->revision($page),
                '_csrfToken' => $this->token($page),
            ]);
            self::assertSame(409, $response['code']);
            $this->assertActive($this->request($stale), []);
        }
    }

    public function testFileCommitFailureDoesNotDisplaySuccess(): void
    {
        $jar = [];
        $this->begin($jar, SessionKind::Guest);
        $page = $this->request($jar);
        $path = dirname($this->guestPath($jar));
        chmod($path, 0500);
        try {
            if (is_writable($path)) {
                self::markTestSkipped('Write permissions cannot be denied to this process.');
            }
            $response = $this->request($jar, [
                'kind' => 'guest',
                'operation' => 'answer',
                'item' => 1,
                'revision' => $this->revision($page),
                '_csrfToken' => $this->token($page),
            ]);
            self::assertSame(503, $response['code']);
            self::assertStringContainsString('読み書きに失敗しました', $response['body']);
            self::assertStringNotContainsString('回答を保存しました', $response['body']);
            self::assertSame('', $this->setCookie($response, SessionKind::Guest));
        } finally {
            chmod($path, 0700);
        }
        self::assertStringContainsString('回答 0 件', $this->request($jar)['body']);
    }

    public function testCapacityPreservesInProgressExercisesAndGuidesBookmarkRemoval(): void
    {
        $jar = [];
        $this->begin($jar, SessionKind::Guest);
        $this->changeGuestRecord($jar, static function (array &$learning): void {
            $learning['exercises'] = [
                10 => ['finished' => 2, 'answers' => 20],
                20 => ['finished' => 0, 'answers' => 450],
                30 => ['finished' => 1, 'answers' => 30],
            ];
            $learning['bookmarks'] = array_fill_keys(range(1, 100), true);
        });
        $page = $this->save($jar, 20);
        self::assertStringContainsString('演習 20 · 451 件', $page['body']);
        self::assertStringContainsString('演習 10 · 20 件', $page['body']);
        self::assertStringNotContainsString('演習 30 ·', $page['body']);

        $blocked = $this->post($jar, 'guest', 'bookmark', ['item' => 101, 'revision' => $this->revision($page)]);
        self::assertSame(409, $blocked['code']);
        self::assertStringContainsString('先に既存のブックマークを解除', $blocked['body']);
        $removed = $this->post($jar, 'guest', 'unbookmark', ['item' => 100, 'revision' => $this->revision($blocked)]);
        self::assertStringContainsString('ブックマーク 99 件', $removed['body']);
        $this->changeGuestRecord($jar, static function (array &$learning): void {
            $learning['exercises'] = [20 => ['finished' => 0, 'answers' => 500]];
        });
        $full = $this->post($jar, 'guest', 'answer', ['item' => 20, 'revision' => $this->revision($removed)]);
        self::assertSame(409, $full['code']);
        self::assertStringContainsString('演習 20 · 500 件', $full['body']);
    }

    public function testPurgeRemovesExpiredFilesAndPreservesActiveOnes(): void
    {
        $guest = $member = $admin = [];
        $this->begin($guest, SessionKind::Guest);
        $this->begin($member, SessionKind::Member);
        $this->begin($admin, SessionKind::Admin);
        $this->clock(86400);
        $now = $this->start + 86400;
        $actual = [];
        foreach (SessionKind::cases() as $kind) {
            $actual[] = (new Sessions(
                new SessionStore($this->directory . '/sessions', $kind),
                $kind,
                static fn(): int => $now,
            ))->purge();
        }
        self::assertSame([1, 0, 1], $actual);
        self::assertFileDoesNotExist($this->guestPath($guest));
        $this->assertActive($this->request($member), ['member']);
        $this->assertActive($this->request($admin), []);
    }

    private function beginAll(array &$jar): void
    {
        foreach (SessionKind::cases() as $kind) {
            $this->begin($jar, $kind);
        }
    }

    private function begin(array &$jar, SessionKind $kind, string $subject = 'sample-a'): array
    {
        $operation = $kind === SessionKind::Guest ? 'create' : 'login';
        $page = $this->post($jar, $kind->value, $operation, ['subject' => $subject]);
        self::assertSame(200, $page['code'], substr(strip_tags($page['body']), 0, 400));

        return $page;
    }

    private function save(array &$jar, int $item = 1): array
    {
        $page = $this->request($jar);
        $saved = $this->post($jar, 'guest', 'answer', ['item' => $item, 'revision' => $this->revision($page)]);
        self::assertSame(200, $saved['code']);

        return $saved;
    }

    private function post(array &$jar, string $kind, string $operation, array $input = []): array
    {
        $page = $this->request($jar);

        return $this->request($jar, $input + [
            'kind' => $kind,
            'operation' => $operation,
            '_csrfToken' => $this->token($page),
        ]);
    }

    private function assertActive(array $page, array $kinds): void
    {
        self::assertSame(200, $page['code']);
        foreach (SessionKind::cases() as $kind) {
            $active = in_array($kind->value, $kinds, true) ? 1 : 0;
            self::assertStringContainsString('data-kind="' . $kind->value . '" data-active="' . $active . '"', $page['body']);
        }
    }

    private function changeGuestRecord(array $jar, callable $change): void
    {
        $path = $this->guestPath($jar);
        $record = json_decode(file_get_contents($path), true, 32, JSON_THROW_ON_ERROR);
        $payload = unserialize(base64_decode($record['payload']), ['allowed_classes' => false]);
        $change($payload['Learning']);
        $record['payload'] = base64_encode(serialize($payload));
        file_put_contents($path, json_encode($record, JSON_THROW_ON_ERROR));
    }

    private function guestPath(array $jar): string
    {
        return $this->directory . '/sessions/guest/' . hash('sha256', $jar[SessionKind::Guest->cookie()]) . '.json';
    }

    private function clock(int $offset = 0): void
    {
        file_put_contents($this->directory . '/clock', (string)($this->start + $offset), LOCK_EX);
    }

    private function mode(string $mode): void
    {
        file_put_contents($this->directory . '/mode', $mode, LOCK_EX);
    }

    private function serve(): void
    {
        $repo = dirname(__DIR__, 3);
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $address = stream_socket_get_name($socket, false);
        fclose($socket);
        $server = proc_open(
            [PHP_BINARY, '-S', $address, '-t', $this->directory, $repo . '/tests/Support/Poc02/router.php'],
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'],
             2 => ['file', $this->directory . '/server.log', 'a']],
            $pipes,
            $repo,
            [
                'POC02_TEST_DIRECTORY' => $this->directory,
                'DEBUG' => '0',
                'APP_FULL_BASE_URL' => 'https://127.0.0.1',
                'DATABASE_URL' => 'sqlite:///:memory:',
                'DATABASE_TEST_URL' => 'sqlite:///:memory:',
            ] + getenv(),
        );
        $this->servers[] = $server;
        $this->urls[] = 'http://' . $address . '/poc02/sessions';
        for ($attempt = 0; $attempt < 100; $attempt++) {
            // phpcs:ignore Generic.PHP.NoSilencedErrors
            $socket = @stream_socket_client('tcp://' . $address, timeout: 0.1);
            if ($socket !== false) {
                fclose($socket);

                return;
            }
            usleep(10000);
        }

        throw new RuntimeException('The local test HTTP server did not start.');
    }

    private function curl(array $jar, ?array $data, int $worker = 0, array $headers = []): CurlHandle
    {
        $curl = curl_init($this->urls[$worker]);
        $cookies = [];
        foreach ($jar as $name => $value) {
            $cookies[] = $name . '=' . $value;
        }
        curl_setopt_array($curl, [
            CURLOPT_COOKIE => implode('; ', $cookies),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_HTTPHEADER => $headers,
        ]);
        if ($data !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($data));
        }

        return $curl;
    }

    private function request(array &$jar, ?array $data = null, int $worker = 0, array $headers = []): array
    {
        $curl = $this->curl($jar, $data, $worker, $headers);
        $raw = curl_exec($curl);
        if ($raw === false) {
            throw new RuntimeException(curl_error($curl));
        }
        $size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
        $headers = explode("\r\n", substr($raw, 0, $size));
        foreach ($headers as $line) {
            if (!preg_match('/^Set-Cookie: ([^=]+)=([^;]*)/i', $line, $match)) {
                continue;
            }
            [, $name, $value] = $match;
            if ($value === '' || $value === 'deleted') {
                unset($jar[$name]);
            } else {
                $jar[$name] = $value;
            }
        }

        return ['code' => curl_getinfo($curl, CURLINFO_RESPONSE_CODE), 'headers' => $headers, 'body' => substr($raw, $size)];
    }

    private function setCookie(array $page, SessionKind $kind): string
    {
        return $this->headerCookie($page, $kind->cookie());
    }

    private function headerCookie(array $page, string $name): string
    {
        foreach ($page['headers'] as $line) {
            if (str_starts_with(strtolower($line), 'set-cookie: ' . strtolower($name) . '=')) {
                return $line;
            }
        }

        return '';
    }

    private function token(array $page): string
    {
        return $this->field($page, '_csrfToken');
    }

    private function revision(array $page): string
    {
        return $this->field($page, 'revision');
    }

    private function field(array $page, string $name): string
    {
        self::assertSame(1, preg_match('/name="' . $name . '" value="([^"]+)"/', $page['body'], $match));

        return html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}
