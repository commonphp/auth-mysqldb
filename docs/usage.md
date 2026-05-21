# MySQL Auth Driver Usage

`MysqlAuthenticationDriver` authenticates CommonPHP credentials against a MySQL table through PDO. It returns CommonPHP `AuthenticationResult` values for expected authentication outcomes and throws MySQL auth driver exceptions for connection, query, configuration, or row hydration failures.

## Basic Setup

```php
<?php

use CommonPHP\Authentication\Credentials;
use CommonPHP\Drivers\Authentication\MySQL\MysqlAuthenticationDriver;

$driver = new MysqlAuthenticationDriver(
    connection: [
        'database' => 'app',
        'username' => 'app_user',
        'password' => 'secret',
        'host' => '127.0.0.1',
        'port' => 3306,
    ],
    options: [
        'table' => 'users',
        'identifierColumn' => 'email',
        'passwordHashColumn' => 'password_hash',
        'activeColumn' => 'active',
        'lockedColumn' => 'locked',
        'credentialsExpiresAtColumn' => 'password_expires_at',
    ],
);

$result = $driver->authenticate(Credentials::password('ada@example.com', 'secret'));
```

## Default Columns

The default table is `users`. The required columns are:

- `id`
- `identifier`
- `password_hash`

Optional identity columns are:

- `name`
- `attributes`
- `roles`
- `permissions`

Optional status columns can be configured with `activeColumn`, `lockedColumn`, and `credentialsExpiresAtColumn`.

## Stored Values

Passwords are verified with PHP `password_verify`, so store hashes produced by `password_hash`.

`attributes` should be a JSON object. `roles` and `permissions` may be JSON arrays or comma-separated strings.

Identifiers, table names, and column names are validated as unquoted SQL identifiers. Table names may include dot-separated schema segments, such as `auth.users`.
