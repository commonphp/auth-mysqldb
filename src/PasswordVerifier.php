<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL;

use CommonPHP\Drivers\Authentication\MySQL\Exceptions\MysqlAuthDriverException;
use Throwable;

final readonly class PasswordVerifier
{
    public function verify(string $secret, string $hash): bool
    {
        if ($hash === '') {
            return false;
        }

        try {
            return password_verify($secret, $hash);
        } catch (Throwable $throwable) {
            throw MysqlAuthDriverException::forPasswordVerification($throwable);
        }
    }
}
