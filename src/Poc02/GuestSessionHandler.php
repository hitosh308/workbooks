<?php
declare(strict_types=1);

namespace App\Poc02;

use Cake\Http\Session;
use RuntimeException;
use SessionHandlerInterface;

/**
 * PHP serializes the CakePHP Session payload here. SessionStore commits it
 * together with its revision and expiry under the same file lock.
 */
final class GuestSessionHandler implements SessionHandlerInterface
{
    private bool $written = false;

    /**
     * Supply the bytes from the locked guest record.
     */
    public function __construct(private string $payload)
    {
    }

    /**
     * Open one CakePHP session and return the serialized state and operation result.
     */
    public function transact(callable $work): array
    {
        if (session_status() !== PHP_SESSION_NONE || headers_sent()) {
            throw new RuntimeException('Native guest session unavailable');
        }
        $settings = [
            'session.use_cookies' => 0,
            'session.use_only_cookies' => 1,
            'session.use_trans_sid' => 0,
            'session.cache_limiter' => '',
            'session.gc_probability' => 0,
            'session.lazy_write' => 0,
            'session.serialize_handler' => 'php_serialize',
            'session.cookie_path' => '/',
        ];
        $previous = array_map('ini_get', array_keys($settings));
        $nativeHandler = ini_get('session.save_handler');
        if ($nativeHandler === 'user') {
            throw new RuntimeException('An application session handler is already installed');
        }
        $nativeId = session_id();
        $nativeData = $_SESSION ?? null;
        set_error_handler(static function (): never {
            throw new RuntimeException('Native guest session operation failed');
        }, E_WARNING);
        try {
            $session = new Session([
                'timeout' => 0,
                'ini' => $settings,
                'handler' => ['engine' => $this],
            ]);
            // PHP's internal ID never leaves this request or selects a stored record.
            $session->id(bin2hex(random_bytes(32)));
            if (!$session->start() || session_status() !== PHP_SESSION_ACTIVE) {
                throw new RuntimeException('Native guest session could not start');
            }
            $result = $work($session);
            $session->close();
            if (!$this->written) {
                throw new RuntimeException('Guest session could not be serialized');
            }

            return [$this->payload, $result];
        } finally {
            try {
                if (session_status() === PHP_SESSION_ACTIVE) {
                    session_abort();
                }
                ini_set('session.save_handler', $nativeHandler);
                foreach (array_combine(array_keys($settings), $previous) as $name => $value) {
                    ini_set($name, $value);
                }
                session_id($nativeId);
                unset($_SESSION);
                if ($nativeData !== null) {
                    $_SESSION = $nativeData;
                }
            } finally {
                restore_error_handler();
            }
        }
    }

    /**
     * Accept the current native session.
     */
    public function open(string $path, string $name): bool
    {
        return true;
    }

    /**
     * Leave persistence to the file transaction.
     */
    public function close(): bool
    {
        return true;
    }

    /**
     * Supply the guest payload to PHP.
     */
    public function read(string $id): string
    {
        return $this->payload;
    }

    /**
     * Capture the serialized payload before the outer transaction commits.
     */
    public function write(string $id, string $data): bool
    {
        $this->payload = $data;
        $this->written = true;

        return true;
    }

    /**
     * Discard the in-memory payload.
     */
    public function destroy(string $id): bool
    {
        $this->payload = '';

        return true;
    }

    /**
     * Leave expiration to the outer store.
     */
    public function gc(int $max_lifetime): int
    {
        return 0;
    }
}
