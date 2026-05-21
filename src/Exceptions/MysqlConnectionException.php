<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL\Exceptions;

use CommonPHP\Drivers\Authentication\MySQL\MysqlConnectionOptions;
use Throwable;

class MysqlConnectionException extends MysqlAuthDriverException
{
    public static function forInvalidOptions(string $message): self
    {
        return new self($message);
    }

    public static function forConnection(MysqlConnectionOptions $options, Throwable $previous): self
    {
        return new self(
            'MySQL auth connection to "' . $options->database() . '" at "' . $options->endpoint() . '" failed.',
            previous: $previous,
        );
    }
}
