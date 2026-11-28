<?php
declare(strict_types=1);

namespace App\Poc02;

use Cake\Chronos\Chronos;
use Cake\Http\Cookie\Cookie;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;

final class Sessions
{
    private Closure $clock;

    /**
     * Set the store, policy, and optional epoch-seconds clock.
     */
    public function __construct(
        private SessionStore $store,
        private SessionKind $kind,
        ?Closure $clock = null,
    ) {
        $this->clock = $clock ?? static fn(): int => Chronos::now()->getTimestamp();
    }

    /**
     * Resolve and update one session under its kind lock.
     */
    public function handle(mixed $id, string $operation, array $input = []): array
    {
        $creates = in_array($operation, ['create', 'login'], true);
        $key = self::key($id);
        if ($key === null && !$creates) {
            return $this->inactive($operation, $id !== null);
        }

        return $this->store->locked(function () use ($key, $id, $operation, $input, $creates): array {
            $now = ($this->clock)();
            $record = $key === null ? null : $this->store->read($key);
            if ($record !== null && !$this->valid($record, $now)) {
                $this->store->remove($key);
                $record = null;
            }

            if ($record === null && !$creates) {
                return $this->inactive($operation, $id !== null);
            }
            if ($operation === 'logout') {
                $this->store->remove($key);

                return ['status' => 200, 'notice' => 'セッションを終了しました。', 'cookie' => $this->cookie()];
            }
            if (in_array($operation, ['revoke', 'disable'], true)) {
                $account = $this->account($record['subject']);
                $account['generation'] = bin2hex(random_bytes(16));
                $account['disabled'] = $operation === 'disable';
                $this->store->write('account-' . $record['subject'], $account);

                return ['status' => 200, 'notice' => '対象の全セッションを失効しました。', 'cookie' => $this->cookie()];
            }

            $newId = null;
            if ($record === null || $operation === 'login') {
                $subject = $operation === 'login' ? ($input['subject'] ?? null) : null;
                if ($operation === 'login' && !in_array($subject, ['sample-a', 'sample-b'], true)) {
                    return ['status' => 422, 'notice' => '検証用アカウントを選択してください。'];
                }
                $account = $subject === null ? null : $this->account($subject);
                if ($account['disabled'] ?? false) {
                    return ['status' => 403, 'notice' => '検証用アカウントは無効です。'];
                }
                if ($record !== null) {
                    $this->store->remove($key);
                }
                $newId = bin2hex(random_bytes(32));
                $key = self::key($newId);
                $record = [
                    'created' => $now,
                    'seen' => $now,
                    'expires' => $now + $this->kind->maximum(),
                ];
                if ($this->kind === SessionKind::Guest) {
                    $record += ['payload' => '', 'revision' => 0, 'notice' => false];
                } else {
                    $record += ['subject' => $subject, 'generation' => $account['generation']];
                }
            }

            $result = ['status' => 200, 'notice' => ''];
            if ($this->kind === SessionKind::Guest) {
                $payload = base64_decode($record['payload'], true);
                if ($payload === false) {
                    throw new RuntimeException('Invalid guest payload');
                }
                $handler = new GuestSessionHandler($payload);
                [$payload, $result] = $handler->transact(
                    static function ($session) use (&$record, $operation, $input): array {
                        return GuestLearning::update($session, $record, $operation, $input);
                    },
                );
                $record['payload'] = base64_encode($payload);
            }
            $record['seen'] = max($record['seen'], $now);
            $this->store->write($key, $record);

            return $result + [
                'active' => true,
                'subject' => $record['subject'] ?? null,
                'expires' => $record['expires'],
                'cookie' => $newId === null ? null : $this->cookie($newId, $record['expires']),
            ];
        });
    }

    /**
     * Remove expired and revoked session records.
     */
    public function purge(): int
    {
        $keys = $this->store->locked(fn(): array => $this->store->sessionKeys());
        $removed = 0;
        foreach ($keys as $key) {
            $removed += $this->store->locked(function () use ($key): int {
                $record = $this->store->read($key);
                if ($record === null || $this->valid($record, ($this->clock)())) {
                    return 0;
                }
                $this->store->remove($key);

                return 1;
            });
        }

        return $removed;
    }

    /**
     * Check the absolute, idle, and account-generation constraints.
     */
    private function valid(array $record, int $now): bool
    {
        if ($now >= $record['expires'] || $now >= $record['seen'] + $this->kind->idle()) {
            return false;
        }
        if ($this->kind === SessionKind::Guest) {
            return true;
        }
        $account = $this->account($record['subject']);

        return !$account['disabled'] && $record['generation'] === $account['generation'];
    }

    /**
     * Read the current authentication generation for a fixture account.
     */
    private function account(string $subject): array
    {
        return $this->store->read('account-' . $subject) ?? ['generation' => '', 'disabled' => false];
    }

    /**
     * Validate a cookie and hash it before using it as a storage key.
     */
    private static function key(mixed $id): ?string
    {
        return is_string($id) && preg_match('/\A[a-f0-9]{64}\z/', $id) === 1 ? hash('sha256', $id) : null;
    }

    /**
     * Return an inactive result and optionally expire the browser cookie.
     */
    private function inactive(string $operation, bool $clearCookie): array
    {
        $read = $operation === 'status';
        $logout = $operation === 'logout';

        return [
            'status' => $read || $logout ? 200 : 409,
            'active' => false,
            'notice' => $read || $logout ? '' : 'セッションが無効です。画面を開き直してください。',
            'cookie' => $clearCookie ? $this->cookie() : null,
        ];
    }

    /**
     * Build the host-only session cookie or its deletion counterpart.
     */
    private function cookie(string $id = '', int $expires = 0): Cookie
    {
        $date = null;
        if ($id === '') {
            $date = new DateTimeImmutable('@1');
        } elseif ($this->kind !== SessionKind::Admin) {
            $date = new DateTimeImmutable('@' . $expires);
        }

        return new Cookie(
            $this->kind->cookie(),
            $id,
            $date?->setTimezone(new DateTimeZone('UTC')),
            '/',
            '',
            true,
            true,
            Cookie::SAMESITE_LAX,
        );
    }
}
