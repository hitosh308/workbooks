<?php
declare(strict_types=1);

namespace App\Poc02;

enum SessionKind: string
{
    case Guest = 'guest';
    case Member = 'member';
    case Admin = 'admin';

    /**
     * Return the inactivity window in seconds.
     */
    public function idle(): int
    {
        return match ($this) {
            self::Guest => 86400,
            self::Member => 604800,
            self::Admin => 1800,
        };
    }

    /**
     * Return the absolute lifetime in seconds.
     */
    public function maximum(): int
    {
        return match ($this) {
            self::Guest => 604800,
            self::Member => 2592000,
            self::Admin => 28800,
        };
    }

    /**
     * Return the host-only cookie name for this session kind.
     */
    public function cookie(): string
    {
        return '__Host-poc02-' . $this->value;
    }
}
