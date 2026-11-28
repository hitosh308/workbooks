<?php
declare(strict_types=1);

namespace App\Poc02;

use Cake\Core\Configure;
use FilesystemIterator;
use RuntimeException;

// File-system warnings can expose storage paths. Check results and return generic errors.
// phpcs:disable Generic.PHP.NoSilencedErrors
final class SessionStore
{
    private string $directory;

    /**
     * Select a private directory for this session kind.
     */
    public function __construct(string $root, SessionKind $kind)
    {
        $this->directory = $root . DIRECTORY_SEPARATOR . $kind->value;
    }

    /**
     * Resolve the PoC storage directory.
     */
    public static function forKind(SessionKind $kind): self
    {
        return new self(Configure::read('Poc02.storage', TMP . 'poc02-sessions'), $kind);
    }

    /**
     * Serialize changes and expiration checks for one session kind.
     */
    public function locked(callable $work): mixed
    {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            throw new RuntimeException('Session storage unavailable');
        }
        $lock = @fopen($this->directory . '/.lock', 'c');
        if ($lock === false) {
            throw new RuntimeException('Session lock unavailable');
        }
        try {
            if (!flock($lock, LOCK_EX)) {
                throw new RuntimeException('Session lock failed');
            }

            return $work();
        } finally {
            fclose($lock);
        }
    }

    /**
     * Load one record while holding the kind lock.
     */
    public function read(string $key): ?array
    {
        $path = $this->directory . '/' . $key . '.json';
        clearstatcache(true, $path);
        if (!is_file($path)) {
            return null;
        }
        $contents = @file_get_contents($path);
        if ($contents === false) {
            throw new RuntimeException('Session read failed');
        }

        return json_decode($contents, true, 32, JSON_THROW_ON_ERROR);
    }

    /**
     * Atomically replace one record under the kind lock.
     */
    public function write(string $key, array $record): void
    {
        $data = json_encode($record, JSON_THROW_ON_ERROR);
        $temp = @tempnam($this->directory, '.pending-');
        if ($temp === false) {
            throw new RuntimeException('Session staging failed');
        }
        try {
            if (
                dirname($temp) !== $this->directory ||
                @file_put_contents($temp, $data) !== strlen($data) ||
                !@rename($temp, $this->directory . '/' . $key . '.json')
            ) {
                throw new RuntimeException('Session commit failed');
            }
        } finally {
            if (is_file($temp)) {
                @unlink($temp);
            }
        }
    }

    /**
     * Remove one record under the kind lock.
     */
    public function remove(string $key): void
    {
        if (!@unlink($this->directory . '/' . $key . '.json')) {
            throw new RuntimeException('Session removal failed');
        }
    }

    /** @return list<string> */
    public function sessionKeys(): array
    {
        $keys = [];
        foreach (new FilesystemIterator($this->directory) as $file) {
            if (preg_match('/\A([a-f0-9]{64})\.json\z/', $file->getFilename(), $match)) {
                $keys[] = $match[1];
            }
        }

        return $keys;
    }
}
