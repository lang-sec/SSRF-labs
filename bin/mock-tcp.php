<?php

declare(strict_types=1);

$address = 'tcp://127.0.0.1:6380';
$server = @stream_socket_server($address, $errorCode, $errorMessage);

if ($server === false) {
    fwrite(STDERR, "Unable to start mock TCP service: {$errorMessage} ({$errorCode})\n");
    exit(1);
}

fwrite(STDOUT, "Mock internal TCP service listening on {$address}\n");

while (true) {
    $connection = @stream_socket_accept($server, -1);
    if ($connection === false) {
        continue;
    }

    stream_set_timeout($connection, 1);
    $request = '';
    while (!feof($connection)) {
        $chunk = fread($connection, 1024);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $request .= $chunk;
        if (strlen($request) >= 4096) {
            break;
        }
    }

    if (str_contains(strtoupper($request), 'FLAG')) {
        fwrite($connection, "+FLAG{SSRF_GOPHER_PIVOT}\r\n");
    } else {
        fwrite($connection, "-ERR unknown command\r\n");
    }

    fclose($connection);
}

