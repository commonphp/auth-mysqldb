<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL;

use CommonPHP\Authentication\Contracts\IdentityInterface;
use CommonPHP\Authentication\Identity;

final readonly class MysqlUserMapper
{
    public function identity(MysqlUserRecord $record): IdentityInterface
    {
        return new Identity(
            $record->id,
            $record->name,
            $record->attributes,
            $record->roles,
            $record->permissions,
        );
    }
}
