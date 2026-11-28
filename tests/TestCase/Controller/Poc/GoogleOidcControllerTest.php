<?php
declare(strict_types=1);

namespace App\Test\TestCase\Controller\Poc;

use App\Poc\GoogleOidc;
use Cake\Http\Client;
use Cake\Http\Client\Response;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

final class GoogleOidcControllerTest extends TestCase
{
    use IntegrationTestTrait;

    private const PATH = '/poc/google-oidc';
    private const CLIENT = 'mock-client.apps.googleusercontent.com';
    private const SESSION = 'Poc.GoogleOidc.';
    private const SUBJECT = 'synthetic-account';
    private const ENVIRONMENT = [
        'POC_GOOGLE_OIDC_ENABLED' => '1',
        'POC_GOOGLE_CLIENT_ID' => self::CLIENT,
        'POC_GOOGLE_CLIENT_SECRET' => 'dummy',
        'POC_GOOGLE_CALLBACK_URL' => 'http://localhost/poc/google-oidc/callback',
    ];

    private array $originalEnvironment = [];

    protected function setUp(): void
    {
        parent::setUp();
        foreach (self::ENVIRONMENT as $name => $value) {
            $this->originalEnvironment[$name] = $_SERVER[$name] ?? null;
            $_SERVER[$name] = $value;
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->originalEnvironment as $name => $value) {
            if ($value === null) {
                unset($_SERVER[$name]);
            } else {
                $_SERVER[$name] = $value;
            }
        }
        parent::tearDown();
    }

    public function testLoginFormAndStart(): void
    {
        $this->get(self::PATH);
        $this->assertResponseOk();
        $this->assertResponseContains('Google ログイン');
        $this->assertHeader('Cache-Control', 'no-store');
        $this->enableCsrfToken();
        $this->post(self::PATH . '/start', ['mode' => 'login']);
        $this->assertResponseCode(303);
        $url = $this->_response->getHeaderLine('Location');
        self::assertStringStartsWith(GoogleOidc::ISSUER . '/o/oauth2/v2/auth?', $url);
        parse_str(parse_url($url, PHP_URL_QUERY), $query);
        $transaction = $this->getSession()->read(self::SESSION . 'transaction');
        self::assertSame('code', $query['response_type']);
        self::assertSame('openid', $query['scope']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame($transaction['state'], $query['state']);
        self::assertSame($transaction['nonce'], $query['nonce']);
        self::assertNotSame($query['nonce'], $query['state']);
        self::assertNotSame($transaction['verifier'], $query['code_challenge']);
    }

    public function testReauthenticationRequest(): void
    {
        $this->session(['Poc' => ['GoogleOidc' => ['subject' => self::SUBJECT]]]);
        $this->enableCsrfToken();
        $this->post(self::PATH . '/start', ['mode' => 'reauth']);
        $this->assertResponseCode(303);
        parse_str(parse_url($this->_response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        self::assertSame('0', $query['max_age']);
        self::assertSame(['id_token' => ['auth_time' => ['essential' => true]]], json_decode($query['claims'], true));
        $this->assertSession(self::SUBJECT, self::SESSION . 'transaction.subject');
    }

    public static function tokenCases(): array
    {
        return [
            'valid login' => [[], false, false, 'authenticated'],
            'nonce mismatch' => [['nonce' => 'wrong'], false, false, 'verification-failed'],
            'invalid signature' => [[], false, true, 'verification-failed'],
            'invalid issuer' => [['iss' => 'https://example.invalid'], false, false, 'verification-failed'],
            'invalid audience' => [['aud' => 'wrong'], false, false, 'verification-failed'],
            'invalid authorized party' => [['azp' => 'wrong'], false, false, 'verification-failed'],
            'expired token' => [['exp' => -1], false, false, 'verification-failed'],
            'same sub and fresh' => [['auth_time' => -1], true, false, 'reauthenticated'],
            'different sub' => [['sub' => 'other', 'auth_time' => -1], true, false, 'different-account'],
            'old authentication' => [['auth_time' => -100], true, false, 'stale'],
            'same-second authentication' => [['auth_time' => -10], true, false, 'stale'],
            'missing freshness' => [[], true, false, 'freshness-unavailable'],
            'future freshness' => [['auth_time' => 60], true, false, 'freshness-unavailable'],
        ];
    }

    #[DataProvider('tokenCases')]
    public function testIdToken(array $overrides, bool $reauth, bool $wrongKey, string $result): void
    {
        $transaction = $this->seedTransaction($reauth);
        $now = $transaction['startedAt'] + 10;
        foreach (['exp', 'auth_time'] as $claim) {
            if (isset($overrides[$claim])) {
                $overrides[$claim] += $now;
            }
        }
        $payload = $overrides + [
            'iss' => GoogleOidc::ISSUER,
            'aud' => self::CLIENT,
            'iat' => $now,
            'exp' => $now + 60,
            'nonce' => $transaction['nonce'],
            'sub' => self::SUBJECT,
        ];

        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $signingKey = $wrongKey
            ? openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048])
            : $key;
        $token = JWT::encode($payload, $signingKey, 'RS256', 'test-key');
        $rsa = openssl_pkey_get_details($key)['rsa'];
        $jwks = ['keys' => [[
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => 'test-key',
            'n' => JWT::urlsafeB64Encode($rsa['n']),
            'e' => JWT::urlsafeB64Encode($rsa['e']),
        ]]];
        $http = $this->createMock(Client::class);
        $http->expects(self::once())->method('post')->with(
            GoogleOidc::TOKEN_URL,
            self::callback(static fn(array $data): bool => (
                $data['code_verifier'] === $transaction['verifier']
                && $data['code'] === 'test-code'
                && $data['grant_type'] === 'authorization_code'
            )),
        )->willReturn($this->googleResponse(['id_token' => $token]));
        $http->expects(self::once())->method('get')->with(GoogleOidc::JWKS_URL)
            ->willReturn($this->googleResponse($jwks));
        $this->mockGoogle($http);

        $this->complete($transaction['state']);
        $this->assertResult($result);
        if ($reauth || $result === 'authenticated') {
            $this->assertSession(self::SUBJECT, self::SESSION . 'subject');
        } else {
            self::assertNull($this->getSession()->read(self::SESSION . 'subject'));
        }
        if ($result === 'authenticated') {
            $this->session($this->getSession()->read());
            $this->complete($transaction['state']);
            $this->assertResult('invalid');
            $this->assertSession(self::SUBJECT, self::SESSION . 'subject');
        }
    }

    public function testExpiredTransaction(): void
    {
        $transaction = $this->seedTransaction();
        $this->session(['Poc' => ['GoogleOidc' => ['transaction' => [
            'startedAt' => time() - GoogleOidc::LIFETIME - 1,
        ] + $transaction]]]);
        $this->expectNoGoogleCalls();

        $this->complete($transaction['state']);
        $this->assertResult('invalid');
    }

    public function testStartRequiresCsrfToken(): void
    {
        $this->post(self::PATH . '/start', ['mode' => 'login']);
        $this->assertResponseCode(403);
    }

    public function testMismatchedState(): void
    {
        $this->seedTransaction();
        $this->expectNoGoogleCalls();
        $this->complete('wrong-state');
        $this->assertResult('invalid');
    }

    public function testCancellationAndReplay(): void
    {
        $transaction = $this->seedTransaction();
        $this->expectNoGoogleCalls();
        $this->get(self::PATH . '/callback?' . http_build_query([
            'state' => $transaction['state'],
            'error' => 'access_denied',
            'error_description' => 'untrusted Google response text',
        ]));
        $this->assertResult('cancelled');

        $this->session($this->getSession()->read());
        $this->complete($transaction['state']);
        $this->assertResult('invalid');
    }

    public function testGoogleTransportFailure(): void
    {
        $transaction = $this->seedTransaction();
        $http = $this->createMock(Client::class);
        $http->expects(self::once())->method('post')->willThrowException(new RuntimeException('Mock timeout'));
        $http->expects(self::never())->method('get');
        $this->mockGoogle($http);

        $this->complete($transaction['state']);
        $this->assertResult('verification-failed');

        $this->get('/');
        $this->assertResponseOk();
    }

    public function testMissingConfigurationAndDisabledRoutes(): void
    {
        $_SERVER['POC_GOOGLE_CLIENT_ID'] = '';
        $this->get(self::PATH);
        $this->assertResponseOk();
        $this->assertResponseContains('検証用 Google OAuth 設定が必要です。');

        $_SERVER['POC_GOOGLE_OIDC_ENABLED'] = '0';
        $this->get(self::PATH);
        $this->assertResponseCode(404);
        $this->enableCsrfToken();
        $this->post(self::PATH . '/start', ['mode' => 'login']);
        $this->assertResponseCode(404);
        $this->get(self::PATH . '/callback');
        $this->assertResponseCode(404);
    }

    private function seedTransaction(bool $reauth = false): array
    {
        $transaction = [
            'state' => 'test-state',
            'nonce' => 'test-nonce',
            'verifier' => 'test-verifier',
            'startedAt' => time() - 10,
            'subject' => $reauth ? self::SUBJECT : null,
        ];
        $session = ['transaction' => $transaction];
        if ($reauth) {
            $session['subject'] = self::SUBJECT;
        }
        $this->session(['Poc' => ['GoogleOidc' => $session]]);

        return $transaction;
    }

    private function complete(string $state): void
    {
        $this->get(self::PATH . '/callback?' . http_build_query([
            'state' => $state,
            'code' => 'test-code',
            'iss' => GoogleOidc::ISSUER,
        ]));
    }

    private function assertResult(string $result): void
    {
        $this->assertResponseCode(303);
        $this->assertRedirect(self::PATH);
        $this->assertHeader('Referrer-Policy', 'no-referrer');
        $this->assertSession($result, self::SESSION . 'result');
        self::assertNull($this->getSession()->read(self::SESSION . 'transaction'));
    }

    private function expectNoGoogleCalls(): void
    {
        $http = $this->createMock(Client::class);
        $http->expects(self::never())->method('post');
        $http->expects(self::never())->method('get');
        $this->mockGoogle($http);
    }

    private function mockGoogle(Client $http): void
    {
        $this->mockService(GoogleOidc::class, static fn(): GoogleOidc => new GoogleOidc(
            $http,
            self::CLIENT,
            'dummy',
            self::ENVIRONMENT['POC_GOOGLE_CALLBACK_URL'],
        ));
    }

    private function googleResponse(array $body): Response
    {
        return new Response(['HTTP/1.1 200 OK', 'Content-Type: application/json'], json_encode($body, JSON_THROW_ON_ERROR));
    }
}
