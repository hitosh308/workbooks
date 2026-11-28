<?php
declare(strict_types=1);

use App\Application;
use Cake\Http\Server;

require dirname(__DIR__) . '/vendor/autoload.php';

if (PHP_SAPI === 'cli-server') {
    $_SERVER['PHP_SELF'] = '/index.php';
}

$server = new Server(new Application(dirname(__DIR__) . '/config'));
$server->emit($server->run());
