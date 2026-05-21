# CommonPHP MySQL Auth Driver

Authentication driver for CommonPHP that uses MySQL as an authentication source.

## Requirements

- PHP `^8.5`
- `ext-pdo`
- `ext-pdo_mysql`
- `comphp/auth:^0.3`
- A MySQL database with a table containing identity and password hash columns

## Installation

Once this package is available through your Composer repositories, install it with:

```bash
composer require comphp/auth-mysqldb
```

## Usage

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
    ],
    options: [
        'table' => 'users',
        'identifierColumn' => 'email',
        'passwordHashColumn' => 'password_hash',
        'activeColumn' => 'active',
        'lockedColumn' => 'locked',
    ],
);

$result = $driver->authenticate(Credentials::password('ada@example.com', 'secret'));

if ($result->isAuthenticated()) {
    $identity = $result->identity();
}
```

## Driver Notes

This driver is intended for applications that store authentication records directly in MySQL without requiring the full CommonPHP database abstraction.

Use `comphp/auth-comphp-database` instead when authentication should go through a CommonPHP Database connection.

By default the driver reads from `users` and expects `id`, `identifier`, and `password_hash` columns. Optional `name`, `attributes`, `roles`, and `permissions` columns hydrate the CommonPHP identity. Optional status columns can mark a user inactive, locked, or expired.

## Error Handling

Connection, query, credential, configuration, and authentication source failures should throw CommonPHP auth driver exceptions instead of returning ambiguous false values.

## Documentation

- [Usage](docs/usage.md)
- [Testing](TESTING.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## License

MIT. See [LICENSE.md](LICENSE.md).
