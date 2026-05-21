<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL\Exceptions;

use Throwable;

class MysqlQueryException extends MysqlAuthDriverException
{
    public static function forOperation(string $operation, string $query, Throwable $previous): self
    {
        return new self(
            'MySQL auth query operation "' . $operation . '" failed for query: ' . self::summarize($query),
            previous: $previous,
        );
    }

    public static function forPrepareFailure(string $query): self
    {
        return new self('MySQL auth query could not be prepared: ' . self::summarize($query));
    }

    public static function forBinding(string|int $parameter, string $query): self
    {
        return new self(
            'MySQL auth query could not bind parameter "' . $parameter . '" for query: ' . self::summarize($query),
        );
    }

    public static function forInvalidParameter(string|int $parameter, string $message): self
    {
        return new self('Invalid MySQL auth query parameter "' . $parameter . '": ' . $message);
    }

    private static function summarize(string $query): string
    {
        $query = trim(preg_replace('/\s+/', ' ', $query) ?? $query);

        return strlen($query) > 160 ? substr($query, 0, 157) . '...' : $query;
    }
}
