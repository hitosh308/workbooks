<?php
declare(strict_types=1);

namespace App\Poc;

use Cake\Http\Client;
use Cake\Http\Client\Response;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use RuntimeException;
use SensitiveParameter;
use function Cake\Core\env;

final class GoogleOidc
{
    public const ISSUER = 'https://accounts.google.com';
    public const TOKEN_URL = 'https://oauth2.googleapis.com/token';
    public const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
    public const LIFETIME = 300;

    /**
     * @param \Cake\Http\Client $http HTTP client for the token and JWKS endpoints.
     * @param string $clientId OAuth web client ID.
     * @param string $clientSecret OAuth web client secret.
     * @param string $callbackUrl Registered redirect URI.
     */
    public function __construct(
        private readonly Client $http,
        private readonly string $clientId,
        #[SensitiveParameter] private readonly string $clientSecret,
        private readonly string $callbackUrl,
    ) {
    }

    /**
     * @return bool Whether the verification routes are explicitly enabled.
     */
    public static function enabled(): bool
    {
        return env('POC_GOOGLE_OIDC_ENABLED', '0') === '1';
    }

    /**
     * @return self Client configured for the Google endpoints.
     */
    public static function fromEnvironment(): self
    {
        return new self(
            new Client(['timeout' => 5, 'redirect' => false, 'ssl_verify_peer' => true, 'ssl_verify_host' => true]),
            (string)env('POC_GOOGLE_CLIENT_ID', ''),
            (string)env('POC_GOOGLE_CLIENT_SECRET', ''),
            (string)env('POC_GOOGLE_CALLBACK_URL', ''),
        );
    }

    /**
     * @return bool Whether the required settings are present and the redirect URI is acceptable.
     */
    public function configured(): bool
    {
        if (
            $this->clientId === '' || $this->clientSecret === ''
            || !filter_var($this->callbackUrl, FILTER_VALIDATE_URL)
        ) {
            return false;
        }

        $url = parse_url($this->callbackUrl);
        if (isset($url['user']) || isset($url['query']) || isset($url['fragment'])) {
            return false;
        }

        return $url['scheme'] === 'https' ||
            ($url['scheme'] === 'http' && in_array($url['host'], ['localhost', '127.0.0.1', '[::1]'], true));
    }

    /**
     * @param string|null $subject Existing PoC subject when reauthenticating.
     * @return array{state: string, nonce: string, verifier: string, startedAt: int, subject: ?string}
     */
    public function transaction(?string $subject): array
    {
        return [
            'state' => bin2hex(random_bytes(32)),
            'nonce' => bin2hex(random_bytes(32)),
            'verifier' => bin2hex(random_bytes(32)),
            'startedAt' => time(),
            'subject' => $subject,
        ];
    }

    /**
     * @param array $transaction Pending server-side transaction.
     * @return string Google authorization URL.
     */
    public function authorizationUrl(array $transaction): string
    {
        $query = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->callbackUrl,
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => $transaction['state'],
            'nonce' => $transaction['nonce'],
            'code_challenge_method' => 'S256',
            'code_challenge' => rtrim(strtr(
                base64_encode(hash('sha256', $transaction['verifier'], true)),
                '+/',
                '-_',
            ), '='),
        ];
        if ($transaction['subject'] !== null) {
            // Probe max_age support. The signed auth_time is the evidence.
            $query['max_age'] = 0;
            $query['claims'] = '{"id_token":{"auth_time":{"essential":true}}}';
        }

        return self::ISSUER . '/o/oauth2/v2/auth?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @param string $code Authorization code returned by Google.
     * @param array $transaction Consumed server-side transaction.
     * @return array{subject: string}|array{error: string}
     */
    public function verify(string $code, array $transaction): array
    {
        $tokens = $this->json($this->http->post(self::TOKEN_URL, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->callbackUrl,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code_verifier' => $transaction['verifier'],
        ]));
        if (!is_string($tokens['id_token'] ?? null)) {
            throw new RuntimeException('Missing ID token');
        }

        $jwks = $this->json($this->http->get(self::JWKS_URL));
        $jwks['keys'] = array_values(array_filter(
            $jwks['keys'] ?? [],
            static fn(array $key): bool => ($key['kty'] ?? null) === 'RSA'
                && ($key['alg'] ?? 'RS256') === 'RS256'
                && ($key['use'] ?? 'sig') === 'sig',
        ));
        $claims = JWT::decode($tokens['id_token'], JWK::parseKeySet($jwks, 'RS256'));
        $now = time();
        if (
            !in_array($claims->iss ?? null, [self::ISSUER, 'accounts.google.com'], true)
            || !in_array($claims->aud ?? null, [$this->clientId, [$this->clientId]], true)
            || (property_exists($claims, 'azp') && $claims->azp !== $this->clientId)
            || !is_int($claims->exp ?? null) || $claims->exp <= $now
            || !is_int($claims->iat ?? null) || $claims->iat <= 0 || $claims->iat > $now
            || !is_string($claims->sub ?? null) || !preg_match('/\A[\x21-\x7E]{1,255}\z/D', $claims->sub)
            || !is_string($claims->nonce ?? null) || !hash_equals($transaction['nonce'], $claims->nonce)
        ) {
            throw new RuntimeException('Invalid ID token claims');
        }

        if ($transaction['subject'] !== null) {
            if (!hash_equals($transaction['subject'], $claims->sub)) {
                return ['error' => 'different-account'];
            }
            if (!is_int($claims->auth_time ?? null)) {
                return ['error' => 'freshness-unavailable'];
            }
            // Reject ambiguity at the same second, since auth_time has second precision.
            if ($claims->auth_time <= $transaction['startedAt'] || $claims->auth_time < $now - self::LIFETIME) {
                return ['error' => 'stale'];
            }
            if ($claims->auth_time > $claims->iat || $claims->auth_time > $now) {
                return ['error' => 'freshness-unavailable'];
            }
        }

        return ['subject' => $claims->sub];
    }

    /**
     * @param \Cake\Http\Client\Response $response Response from a Google endpoint.
     * @return array Decoded JSON response.
     */
    private function json(Response $response): array
    {
        if (!$response->isOk()) {
            throw new RuntimeException('Google HTTP request failed');
        }

        $data = json_decode($response->getStringBody(), true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new RuntimeException('Invalid Google HTTP response');
        }

        return $data;
    }
}
