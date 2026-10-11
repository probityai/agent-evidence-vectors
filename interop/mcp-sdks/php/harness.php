<?php
// Decode each JSON-RPC line with Mcp\JsonRpc\MessageFactory (json_decode with
// JSON_THROW_ON_ERROR, assoc arrays) and re-encode it the way
// Mcp\Server\Protocol does: json_encode($message, JSON_THROW_ON_ERROR).
declare(strict_types=1);

require __DIR__.'/vendor/autoload.php';

use Mcp\Exception\InvalidInputMessageException;
use Mcp\JsonRpc\MessageFactory;

$factory = MessageFactory::make();
while (false !== ($line = fgets(\STDIN))) {
    $line = rtrim($line, "\n");
    try {
        $messages = $factory->create($line);
        $message = $messages[0];
        if ($message instanceof InvalidInputMessageException) {
            echo 'ERR ', str_replace("\n", ' ', $message->getMessage()), "\n";
            continue;
        }
        $wire = json_encode($message, \JSON_THROW_ON_ERROR);
        echo 'OK ', base64_encode($wire), "\n";
    } catch (\JsonException $e) {
        echo 'ERR JsonException: ', str_replace("\n", ' ', $e->getMessage()), "\n";
    }
}
