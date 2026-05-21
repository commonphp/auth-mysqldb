<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL;

use CommonPHP\Drivers\Authentication\MySQL\Exceptions\MysqlAuthDriverException;

final readonly class MysqlAuthOptions
{
    public const string DEFAULT_TABLE = 'users';

    public const string DEFAULT_IDENTITY_COLUMN = 'id';

    public const string DEFAULT_IDENTIFIER_COLUMN = 'identifier';

    public const string DEFAULT_PASSWORD_HASH_COLUMN = 'password_hash';

    public const string DEFAULT_NAME_COLUMN = 'name';

    public const string DEFAULT_ATTRIBUTES_COLUMN = 'attributes';

    public const string DEFAULT_ROLES_COLUMN = 'roles';

    public const string DEFAULT_PERMISSIONS_COLUMN = 'permissions';

    public const string DEFAULT_IDENTIFIER_PARAMETER = 'identifier';

    public string $table;

    public string $identityColumn;

    public string $identifierColumn;

    public string $passwordHashColumn;

    public ?string $nameColumn;

    public ?string $attributesColumn;

    public ?string $rolesColumn;

    public ?string $permissionsColumn;

    public ?string $activeColumn;

    public ?string $lockedColumn;

    public ?string $credentialsExpiresAtColumn;

    public string $identifierParameter;

    public function __construct(
        string $table = self::DEFAULT_TABLE,
        string $identityColumn = self::DEFAULT_IDENTITY_COLUMN,
        string $identifierColumn = self::DEFAULT_IDENTIFIER_COLUMN,
        string $passwordHashColumn = self::DEFAULT_PASSWORD_HASH_COLUMN,
        ?string $nameColumn = self::DEFAULT_NAME_COLUMN,
        ?string $attributesColumn = self::DEFAULT_ATTRIBUTES_COLUMN,
        ?string $rolesColumn = self::DEFAULT_ROLES_COLUMN,
        ?string $permissionsColumn = self::DEFAULT_PERMISSIONS_COLUMN,
        ?string $activeColumn = null,
        ?string $lockedColumn = null,
        ?string $credentialsExpiresAtColumn = null,
        string $identifierParameter = self::DEFAULT_IDENTIFIER_PARAMETER,
    ) {
        $this->table = self::identifierPath($table, 'table');
        $this->identityColumn = self::identifier($identityColumn, 'identityColumn');
        $this->identifierColumn = self::identifier($identifierColumn, 'identifierColumn');
        $this->passwordHashColumn = self::identifier($passwordHashColumn, 'passwordHashColumn');
        $this->nameColumn = self::nullableIdentifier($nameColumn, 'nameColumn');
        $this->attributesColumn = self::nullableIdentifier($attributesColumn, 'attributesColumn');
        $this->rolesColumn = self::nullableIdentifier($rolesColumn, 'rolesColumn');
        $this->permissionsColumn = self::nullableIdentifier($permissionsColumn, 'permissionsColumn');
        $this->activeColumn = self::nullableIdentifier($activeColumn, 'activeColumn');
        $this->lockedColumn = self::nullableIdentifier($lockedColumn, 'lockedColumn');
        $this->credentialsExpiresAtColumn = self::nullableIdentifier(
            $credentialsExpiresAtColumn,
            'credentialsExpiresAtColumn',
        );
        $this->identifierParameter = self::identifier($identifierParameter, 'identifierParameter');
    }

    /**
     * @param array<string, mixed> $options
     */
    public static function fromArray(array $options): self
    {
        return new self(
            table: self::stringOption($options, ['table'], self::DEFAULT_TABLE),
            identityColumn: self::stringOption(
                $options,
                ['identityColumn', 'identity_column', 'idColumn', 'id_column'],
                self::DEFAULT_IDENTITY_COLUMN,
            ),
            identifierColumn: self::stringOption(
                $options,
                ['identifierColumn', 'identifier_column', 'loginColumn', 'login_column'],
                self::DEFAULT_IDENTIFIER_COLUMN,
            ),
            passwordHashColumn: self::stringOption(
                $options,
                ['passwordHashColumn', 'password_hash_column', 'passwordColumn', 'password_column', 'secretColumn'],
                self::DEFAULT_PASSWORD_HASH_COLUMN,
            ),
            nameColumn: self::nullableStringOption(
                $options,
                ['nameColumn', 'name_column', 'displayNameColumn', 'display_name_column'],
                self::DEFAULT_NAME_COLUMN,
            ),
            attributesColumn: self::nullableStringOption(
                $options,
                ['attributesColumn', 'attributes_column'],
                self::DEFAULT_ATTRIBUTES_COLUMN,
            ),
            rolesColumn: self::nullableStringOption(
                $options,
                ['rolesColumn', 'roles_column'],
                self::DEFAULT_ROLES_COLUMN,
            ),
            permissionsColumn: self::nullableStringOption(
                $options,
                ['permissionsColumn', 'permissions_column'],
                self::DEFAULT_PERMISSIONS_COLUMN,
            ),
            activeColumn: self::nullableStringOption($options, ['activeColumn', 'active_column']),
            lockedColumn: self::nullableStringOption($options, ['lockedColumn', 'locked_column']),
            credentialsExpiresAtColumn: self::nullableStringOption(
                $options,
                [
                    'credentialsExpiresAtColumn',
                    'credentials_expires_at_column',
                    'passwordExpiresAtColumn',
                    'password_expires_at_column',
                ],
            ),
            identifierParameter: self::stringOption(
                $options,
                ['identifierParameter', 'identifier_parameter'],
                self::DEFAULT_IDENTIFIER_PARAMETER,
            ),
        );
    }

    /**
     * @return list<string>
     */
    public function selectedColumns(): array
    {
        $columns = [
            $this->identityColumn,
            $this->identifierColumn,
            $this->passwordHashColumn,
            $this->nameColumn,
            $this->attributesColumn,
            $this->rolesColumn,
            $this->permissionsColumn,
            $this->activeColumn,
            $this->lockedColumn,
            $this->credentialsExpiresAtColumn,
        ];

        $selected = [];

        foreach ($columns as $column) {
            if ($column !== null && !in_array($column, $selected, true)) {
                $selected[] = $column;
            }
        }

        return $selected;
    }

    public function columns(): string
    {
        return implode(', ', array_map(self::quoteIdentifier(...), $this->selectedColumns()));
    }

    public function identityWhereSql(): string
    {
        return self::quoteIdentifier($this->identifierColumn) . ' = :' . $this->identifierParameter;
    }

    public function selectSql(): string
    {
        return 'select ' . $this->columns()
            . ' from ' . self::quoteIdentifierPath($this->table)
            . ' where ' . $this->identityWhereSql()
            . ' limit 1';
    }

    /**
     * @return array<string, string>
     */
    public function lookupParameters(string $identifier): array
    {
        return [$this->identifierParameter => $identifier];
    }

    private static function quoteIdentifier(string $identifier): string
    {
        return '`' . $identifier . '`';
    }

    private static function quoteIdentifierPath(string $identifier): string
    {
        return implode('.', array_map(self::quoteIdentifier(...), explode('.', $identifier)));
    }

    private static function identifierPath(string $value, string $option): string
    {
        $value = trim($value);

        if ($value === '') {
            throw MysqlAuthDriverException::invalidOption($option, 'value cannot be empty.');
        }

        foreach (explode('.', $value) as $segment) {
            self::assertIdentifier($segment, $option);
        }

        return $value;
    }

    private static function identifier(string $value, string $option): string
    {
        $value = trim($value);

        self::assertIdentifier($value, $option);

        return $value;
    }

    private static function nullableIdentifier(?string $value, string $option): ?string
    {
        if ($value === null) {
            return null;
        }

        return self::identifier($value, $option);
    }

    private static function assertIdentifier(string $value, string $option): void
    {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $value) !== 1) {
            throw MysqlAuthDriverException::invalidOption(
                $option,
                'value must be an unquoted SQL identifier using letters, numbers, and underscores.',
            );
        }
    }

    /**
     * @param array<string, mixed> $options
     * @param list<string> $keys
     */
    private static function value(array $options, array $keys): mixed
    {
        foreach ($keys as $key) {
            if (array_key_exists($key, $options)) {
                return $options[$key];
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $options
     * @param list<string> $keys
     */
    private static function stringOption(array $options, array $keys, string $default): string
    {
        $value = self::value($options, $keys);

        if ($value === null) {
            return $default;
        }

        if (!is_string($value)) {
            throw MysqlAuthDriverException::invalidOption($keys[0], 'value must be a string.');
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $options
     * @param list<string> $keys
     */
    private static function nullableStringOption(array $options, array $keys, ?string $default = null): ?string
    {
        foreach ($keys as $key) {
            if (!array_key_exists($key, $options)) {
                continue;
            }

            $value = $options[$key];

            if ($value === null) {
                return null;
            }

            if (!is_string($value)) {
                throw MysqlAuthDriverException::invalidOption($key, 'value must be a string or null.');
            }

            return $value;
        }

        return $default;
    }
}
