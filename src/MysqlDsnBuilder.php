<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL;

final class MysqlDsnBuilder
{
    public function build(MysqlConnectionOptions $options): string
    {
        $parts = [];

        if ($options->unixSocket() !== null) {
            $parts['unix_socket'] = $options->unixSocket();
        } else {
            $parts['host'] = $options->host();
            $parts['port'] = (string) $options->port();
        }

        $parts['dbname'] = $options->database();
        $parts['charset'] = $options->charset();

        return 'mysql:' . implode(';', array_map(
            static fn (string $key, string $value): string => $key . '=' . $value,
            array_keys($parts),
            $parts,
        ));
    }
}
