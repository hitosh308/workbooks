<?php
declare(strict_types=1);

use App\Application;
use Cake\Chronos\Chronos;
use Cake\Core\Configure;
use Cake\Http\Server;

if (PHP_SAPI !== 'cli-server' || getenv('POC02_TEST_DIRECTORY') === false) {
    http_response_code(404);

    return;
}

$repo = dirname(__DIR__, 3);
require $repo . '/vendor/autoload.php';

// PHP's built-in server speaks HTTP. This fixture simulates the HTTPS flag
// from a TLS-terminating web server. The mode file is local to the test runner.
$directory = getenv('POC02_TEST_DIRECTORY');
$mode = file_get_contents($directory . '/mode');
putenv('POC02_ENABLED=' . ($mode === 'disabled' ? '0' : '1'));
putenv('APP_ENV=' . ($mode === 'normal' ? 'production' : 'poc02-isolated'));
if ($mode !== 'http') {
    $_SERVER['HTTPS'] = $mode === 'https-off' ? 'off' : 'on';
}
$_SERVER['PHP_SELF'] = '/index.php';
$_SERVER['SCRIPT_NAME'] = '/index.php';
$app = new class ($repo . '/config') extends Application {
    public function bootstrap(): void
    {
        parent::bootstrap();
        $directory = getenv('POC02_TEST_DIRECTORY');
        Configure::write('Poc02.storage', $directory . '/sessions');
        Chronos::setTestNow(Chronos::createFromTimestamp((int)file_get_contents($directory . '/clock')));
    }
};
$server = new Server($app);
$server->emit($server->run());
