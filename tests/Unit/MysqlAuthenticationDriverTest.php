<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL\Tests\Unit;

use CommonPHP\Authentication\Contracts\AuthenticationDriverInterface;
use CommonPHP\Authentication\Credentials;
use CommonPHP\Authentication\Enums\AuthenticationStatus;
use CommonPHP\Drivers\Authentication\MySQL\Exceptions\MysqlAuthDriverException;
use CommonPHP\Drivers\Authentication\MySQL\Exceptions\MysqlConnectionException;
use CommonPHP\Drivers\Authentication\MySQL\MysqlAuthenticationDriver;
use CommonPHP\Drivers\Authentication\MySQL\MysqlAuthOptions;
use CommonPHP\Drivers\Authentication\MySQL\MysqlConnectionOptions;
use CommonPHP\Drivers\Authentication\MySQL\MysqlDsnBuilder;
use CommonPHP\Runtime\Contracts\DriverInterface;
use PDO;
use PDOException;
use PDOStatement;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class MysqlAuthenticationDriverTest extends TestCase
{
    public function testConnectionOptionsAndDsnBuilderExposeMysqlDefaults(): void
    {
        $options = new MysqlConnectionOptions(
            username: 'app',
            password: 'secret',
            host: 'db.internal',
            database: 'auth',
            port: 3307,
            timeout: 5,
            persistent: true,
        );

        self::assertSame('mysql:host=db.internal;port=3307;dbname=auth;charset=utf8mb4', (new MysqlDsnBuilder())->build($options));
        self::assertSame('db.internal:3307', $options->endpoint());
        self::assertSame(PDO::ERRMODE_EXCEPTION, $options->pdoAttributes()[PDO::ATTR_ERRMODE]);
        self::assertSame(5, $options->pdoAttributes()[PDO::ATTR_TIMEOUT]);
        self::assertTrue($options->pdoAttributes()[PDO::ATTR_PERSISTENT]);
    }

    public function testConnectionOptionsRejectInvalidValues(): void
    {
        $this->expectException(MysqlConnectionException::class);

        new MysqlConnectionOptions(database: '', port: 0);
    }

    public function testItAuthenticatesMysqlUsersAndMapsIdentities(): void
    {
        $pdo = new FakeMysqlAuthPdo();
        $pdo->seed([
            'id' => '1',
            'identifier' => 'ada@example.com',
            'password_hash' => password_hash('secret', PASSWORD_DEFAULT),
            'name' => 'Ada Lovelace',
            'attributes' => '{"tenant":"example"}',
            'roles' => '["admin"]',
            'permissions' => 'reports.read,reports.write',
        ]);
        $driver = new MysqlAuthenticationDriver($pdo);

        $result = $driver->authenticate(Credentials::password('ada@example.com', 'secret'));

        self::assertInstanceOf(AuthenticationDriverInterface::class, $driver);
        self::assertInstanceOf(DriverInterface::class, $driver);
        self::assertTrue($result->isAuthenticated());
        self::assertSame('1', $result->identity()?->id());
        self::assertSame('Ada Lovelace', $result->identity()?->name());
        self::assertSame('example', $result->identity()?->attribute('tenant'));
        self::assertSame(['admin'], $result->identity()?->roleNames());
        self::assertSame(['reports.read', 'reports.write'], $result->identity()?->directPermissionNames());
        self::assertSame('mysql-auth', $result->detail('driver'));
        self::assertSame('ada@example.com', $result->detail('identifier'));
        self::assertSame(
            'select `id`, `identifier`, `password_hash`, `name`, `attributes`, `roles`, `permissions` from `users` where `identifier` = :identifier limit 1',
            $pdo->log[0]['query'],
        );
    }

    public function testItReturnsExpectedResultsForMissingAndInvalidCredentials(): void
    {
        $pdo = new FakeMysqlAuthPdo();
        $pdo->seed([
            'id' => '1',
            'identifier' => 'ada',
            'password_hash' => password_hash('secret', PASSWORD_DEFAULT),
        ]);
        $driver = new MysqlAuthenticationDriver(
            $pdo,
            [
                'nameColumn' => null,
                'attributesColumn' => null,
                'rolesColumn' => null,
                'permissionsColumn' => null,
            ],
        );

        self::assertFalse($driver->supports(new Credentials('ada')));
        self::assertSame(
            AuthenticationStatus::InvalidCredentials,
            $driver->authenticate(new Credentials('ada'))->status(),
        );
        self::assertSame(
            AuthenticationStatus::IdentityNotFound,
            $driver->authenticate(Credentials::password('missing', 'secret'))->status(),
        );
        self::assertSame(
            AuthenticationStatus::InvalidCredentials,
            $driver->authenticate(Credentials::password('ada', 'wrong'))->status(),
        );
    }

    public function testItSupportsOptionalStatusColumns(): void
    {
        $pdo = new FakeMysqlAuthPdo();
        $options = new MysqlAuthOptions(
            nameColumn: null,
            attributesColumn: null,
            rolesColumn: null,
            permissionsColumn: null,
            activeColumn: 'active',
            lockedColumn: 'locked',
            credentialsExpiresAtColumn: 'password_expires_at',
        );
        $driver = new MysqlAuthenticationDriver($pdo, $options);

        $pdo->seed([
            'id' => 'inactive',
            'identifier' => 'inactive',
            'password_hash' => password_hash('secret', PASSWORD_DEFAULT),
            'active' => 0,
            'locked' => 0,
            'password_expires_at' => null,
        ]);
        $pdo->seed([
            'id' => 'locked',
            'identifier' => 'locked',
            'password_hash' => password_hash('secret', PASSWORD_DEFAULT),
            'active' => 1,
            'locked' => 1,
            'password_expires_at' => null,
        ]);
        $pdo->seed([
            'id' => 'expired',
            'identifier' => 'expired',
            'password_hash' => password_hash('secret', PASSWORD_DEFAULT),
            'active' => 1,
            'locked' => 0,
            'password_expires_at' => '2000-01-01 00:00:00',
        ]);

        self::assertSame(
            AuthenticationStatus::Failed,
            $driver->authenticate(Credentials::password('inactive', 'secret'))->status(),
        );
        self::assertSame(
            AuthenticationStatus::Locked,
            $driver->authenticate(Credentials::password('locked', 'secret'))->status(),
        );
        self::assertSame(
            AuthenticationStatus::Expired,
            $driver->authenticate(Credentials::password('expired', 'secret'))->status(),
        );
    }

    public function testItRejectsInvalidOptionsAndCorruptRows(): void
    {
        $this->expectException(MysqlAuthDriverException::class);

        new MysqlAuthOptions(table: 'users; drop table users');
    }

    public function testCorruptJsonAttributesThrowDriverExceptions(): void
    {
        $pdo = new FakeMysqlAuthPdo();
        $pdo->seed([
            'id' => '1',
            'identifier' => 'ada',
            'password_hash' => password_hash('secret', PASSWORD_DEFAULT),
            'name' => 'Ada',
            'attributes' => '{',
            'roles' => '[]',
            'permissions' => '[]',
        ]);
        $driver = new MysqlAuthenticationDriver($pdo);

        $this->expectException(MysqlAuthDriverException::class);

        $driver->authenticate(Credentials::password('ada', 'secret'));
    }
}

final class FakeMysqlAuthPdo extends PDO
{
    /**
     * @var array<string, array<string, mixed>>
     */
    private array $rows = [];

    /**
     * @var list<array{query: string, parameters: array<string|int, mixed>}>
     */
    public array $log = [];

    public function __construct()
    {
    }

    public function prepare(string $query, array $options = []): PDOStatement|false
    {
        return new FakeMysqlAuthStatement($this, $query);
    }

    public function query(string $query, ?int $fetchMode = null, mixed ...$fetchModeArgs): PDOStatement|false
    {
        $statement = new FakeMysqlAuthStatement($this, $query);
        $statement->execute();

        return $statement;
    }

    /**
     * @param array<string, mixed> $row
     */
    public function seed(array $row): void
    {
        $identifier = $row['identifier'] ?? null;

        if (!is_string($identifier)) {
            throw new RuntimeException('Fake MySQL auth rows require an identifier string.');
        }

        $this->rows[$identifier] = $row;
    }

    /**
     * @param array<string|int, mixed> $bindings
     * @return array{rows: list<array<string, mixed>>, affectedRows: int}
     */
    public function executePrepared(string $query, array $bindings): array
    {
        $this->log[] = ['query' => $query, 'parameters' => $bindings];
        $normalized = strtolower(trim(preg_replace('/\s+/', ' ', $query) ?? $query));

        if ($normalized === 'select 1') {
            return ['rows' => [['value' => 1]], 'affectedRows' => 0];
        }

        if (
            str_starts_with($normalized, 'select ')
            && str_contains($normalized, ' from `users` where `identifier` = :identifier limit 1')
        ) {
            $row = $this->rows[(string) $bindings[':identifier']] ?? null;

            return ['rows' => $row === null ? [] : [$row], 'affectedRows' => 0];
        }

        throw new PDOException('Unsupported fake MySQL auth query: ' . $query);
    }
}

final class FakeMysqlAuthStatement extends PDOStatement
{
    /**
     * @var array<string|int, mixed>
     */
    private array $bindings = [];

    /**
     * @var list<array<string, mixed>>
     */
    private array $rows = [];

    private int $affectedRows = 0;

    public function __construct(
        private readonly FakeMysqlAuthPdo $pdo,
        private readonly string $query,
    ) {
    }

    public function bindValue(string|int $param, mixed $value, int $type = PDO::PARAM_STR): bool
    {
        $this->bindings[$param] = $value;

        return true;
    }

    public function execute(?array $params = null): bool
    {
        if ($params !== null) {
            $this->bindings = $params;
        }

        $result = $this->pdo->executePrepared($this->query, $this->bindings);
        $this->rows = $result['rows'];
        $this->affectedRows = $result['affectedRows'];

        return true;
    }

    public function fetch(
        int $mode = PDO::FETCH_DEFAULT,
        int $cursorOrientation = PDO::FETCH_ORI_NEXT,
        int $cursorOffset = 0,
    ): mixed {
        $row = array_shift($this->rows);

        return $row === null ? false : $this->mapRow($row, $mode);
    }

    public function fetchAll(int $mode = PDO::FETCH_DEFAULT, mixed ...$args): array
    {
        return array_map(fn (array $row): mixed => $this->mapRow($row, $mode), $this->rows);
    }

    public function rowCount(): int
    {
        return $this->affectedRows;
    }

    /**
     * @param array<string, mixed> $row
     */
    private function mapRow(array $row, int $mode): mixed
    {
        return match ($mode) {
            PDO::FETCH_NUM => array_values($row),
            PDO::FETCH_BOTH => array_values($row) + $row,
            PDO::FETCH_OBJ => (object) $row,
            PDO::FETCH_COLUMN => array_values($row)[0] ?? null,
            default => $row,
        };
    }
}
