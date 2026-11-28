<?php
declare(strict_types=1);

namespace App\Middleware;

use Cake\Core\Configure;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class Poc02AccessMiddleware implements MiddlewareInterface
{
    /**
     * Require both environment signals for the isolated PoC.
     */
    public static function enabled(): bool
    {
        return getenv('POC02_ENABLED') === '1' && getenv('APP_ENV') === 'poc02-isolated';
    }

    /**
     * Require HTTPS from server configuration and keep debug tooling outside the PoC.
     */
    public static function allows(ServerRequestInterface $request): bool
    {
        $https = strtolower((string)($request->getServerParams()['HTTPS'] ?? ''));

        return self::enabled() && !Configure::read('debug') && $request->getUri()->getScheme() === 'https' &&
            in_array($https, ['on', '1'], true) && $request->getAttribute('webroot') === '/';
    }

    /**
     * Enforce the PoC gate and select the appropriate CakePHP CSRF middleware.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (($request->getAttribute('params')['prefix'] ?? null) !== 'Poc02') {
            return (new CsrfProtectionMiddleware(['httponly' => true]))->process($request, $handler);
        }

        if (!self::allows($request)) {
            return new Response(['status' => 404, 'headers' => ['Cache-Control' => 'no-store']]);
        }

        $response = (new CsrfProtectionMiddleware([
            'cookieName' => '__Host-poc02-csrf',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]))->process($request, $handler);

        return $response->withHeader('Cache-Control', 'no-store, private');
    }
}
