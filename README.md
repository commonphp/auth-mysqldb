# CommonPHP MySQL Auth Driver

Authentication driver for CommonPHP that uses MySQL as an authentication source.

## Requirements

- PHP `^8.5`
- `comphp/auth:^0.3`
- A MySQL database driver or extension supported by the implementation

## Installation

Once this package is available through your Composer repositories, install it with:

```bash
composer require comphp/auth-mysqldb
```

## Usage

```php
<?php

// TODO: Write usage
```

## Driver Notes

This driver is intended for applications that store authentication records directly in MySQL without requiring the full CommonPHP database abstraction.

Use `comphp/auth-comphp-database` instead when authentication should go through a CommonPHP Database connection.

## Error Handling

Connection, query, credential, configuration, and authentication source failures should throw CommonPHP auth driver exceptions instead of returning ambiguous false values.

## Documentation

- [Usage](docs/usage.md)
- [Testing](TESTING.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## License

MIT. See [LICENSE.md](LICENSE.md).
