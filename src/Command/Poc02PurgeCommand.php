<?php
declare(strict_types=1);

namespace App\Command;

use App\Middleware\Poc02AccessMiddleware;
use App\Poc02\SessionKind;
use App\Poc02\Sessions;
use App\Poc02\SessionStore;
use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Exception;

final class Poc02PurgeCommand extends Command
{
    /**
     * Purge inactive PoC records from the isolated environment.
     */
    public function execute(Arguments $args, ConsoleIo $io): int
    {
        if (!Poc02AccessMiddleware::enabled()) {
            $io->err('POC-02 is disabled.');

            return self::CODE_ERROR;
        }

        $removed = 0;
        try {
            foreach (SessionKind::cases() as $kind) {
                $removed += (new Sessions(SessionStore::forKind($kind), $kind))->purge();
            }
        } catch (Exception) {
            $io->err('POC-02 session cleanup failed.');

            return self::CODE_ERROR;
        }

        $io->out(sprintf('Removed %d inactive sessions.', $removed));

        return self::CODE_SUCCESS;
    }
}
