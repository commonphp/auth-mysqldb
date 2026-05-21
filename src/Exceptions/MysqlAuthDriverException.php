<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL\Exceptions;

use CommonPHP\Authentication\Exceptions\AuthenticationDriverException;
use Throwable;

class MysqlAuthDriverException extends AuthenticationDriverException
{
    public static function invalidOption(string $option, string $message): self
    {
        return new self('Invalid MySQL auth option "' . $option . '": ' . $message);
    }

    public static function forLookup(string $identifier, Throwable $previous): self
    {
        return new self('Unable to look up MySQL auth identity "' . $identifier . '".', previous: $previous);
    }

    public static function forHydration(string $message, ?Throwable $previous = null): self
    {
        return new self('Unable to hydrate MySQL auth identity: ' . $message, previous: $previous);
    }

    public static function forPasswordVerification(?Throwable $previous = null): self
    {
        return new self('Unable to verify MySQL auth credentials.', previous: $previous);
    }
}
