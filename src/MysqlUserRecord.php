<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL;

use CommonPHP\Drivers\Authentication\MySQL\Exceptions\MysqlAuthDriverException;
use DateTimeImmutable;
use DateTimeInterface;
use Stringable;
use Throwable;

final readonly class MysqlUserRecord
{
    /**
     * @param array<string, mixed> $attributes
     * @param list<string> $roles
     * @param list<string> $permissions
     */
    public function __construct(
        public string $id,
        public string $identifier,
        public string $passwordHash,
        public ?string $name = null,
        public array $attributes = [],
        public array $roles = [],
        public array $permissions = [],
        public bool $active = true,
        public bool $locked = false,
        public ?DateTimeImmutable $credentialsExpiresAt = null,
    ) {
        if ($this->id === '') {
            throw MysqlAuthDriverException::forHydration('identity id cannot be empty.');
        }

        if ($this->identifier === '') {
            throw MysqlAuthDriverException::forHydration('identifier cannot be empty.');
        }

        if ($this->passwordHash === '') {
            throw MysqlAuthDriverException::forHydration('password hash cannot be empty.');
        }
    }

    /**
     * @param array<string|int, mixed> $row
     */
    public static function fromRow(array $row, MysqlAuthOptions $options): self
    {
        return new self(
            id: self::stringValue($row, $options->identityColumn),
            identifier: self::stringValue($row, $options->identifierColumn),
            passwordHash: self::stringValue($row, $options->passwordHashColumn),
            name: self::nullableStringValue($row, $options->nameColumn),
            attributes: self::attributesValue($row, $options->attributesColumn),
            roles: self::listValue($row, $options->rolesColumn),
            permissions: self::listValue($row, $options->permissionsColumn),
            active: self::optionalBoolValue($row, $options->activeColumn, true),
            locked: self::optionalBoolValue($row, $options->lockedColumn, false),
            credentialsExpiresAt: self::optionalDateTimeValue($row, $options->credentialsExpiresAtColumn),
        );
    }

    public function credentialsExpired(?DateTimeImmutable $now = null): bool
    {
        if ($this->credentialsExpiresAt === null) {
            return false;
        }

        $now ??= new DateTimeImmutable();

        return $this->credentialsExpiresAt <= $now;
    }

    /**
     * @param array<string|int, mixed> $row
     */
    private static function stringValue(array $row, string $column): string
    {
        if (!array_key_exists($column, $row)) {
            throw MysqlAuthDriverException::forHydration('missing column "' . $column . '".');
        }

        $value = $row[$column];

        if (is_scalar($value) || $value instanceof Stringable) {
            return trim((string) $value);
        }

        throw MysqlAuthDriverException::forHydration('column "' . $column . '" is not scalar.');
    }

    /**
     * @param array<string|int, mixed> $row
     */
    private static function nullableStringValue(array $row, ?string $column): ?string
    {
        if ($column === null || !array_key_exists($column, $row) || $row[$column] === null) {
            return null;
        }

        $value = $row[$column];

        if (is_scalar($value) || $value instanceof Stringable) {
            $value = trim((string) $value);

            return $value === '' ? null : $value;
        }

        throw MysqlAuthDriverException::forHydration('column "' . $column . '" is not scalar.');
    }

    /**
     * @param array<string|int, mixed> $row
     * @return array<string, mixed>
     */
    private static function attributesValue(array $row, ?string $column): array
    {
        if ($column === null || !array_key_exists($column, $row) || $row[$column] === null || $row[$column] === '') {
            return [];
        }

        $value = $row[$column];

        if (is_array($value)) {
            return self::normalizeAttributes($value, $column);
        }

        if (!is_string($value)) {
            throw MysqlAuthDriverException::forHydration('column "' . $column . '" is not JSON text.');
        }

        try {
            $decoded = json_decode($value, true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable $throwable) {
            throw MysqlAuthDriverException::forHydration(
                'column "' . $column . '" contains invalid JSON.',
                $throwable,
            );
        }

        if ($decoded === null) {
            return [];
        }

        if (!is_array($decoded)) {
            throw MysqlAuthDriverException::forHydration(
                'column "' . $column . '" did not decode to an object.',
            );
        }

        return self::normalizeAttributes($decoded, $column);
    }

    /**
     * @param array<string|int, mixed> $row
     * @return list<string>
     */
    private static function listValue(array $row, ?string $column): array
    {
        if ($column === null || !array_key_exists($column, $row) || $row[$column] === null || $row[$column] === '') {
            return [];
        }

        $value = $row[$column];

        if (is_array($value)) {
            return self::normalizeList($value);
        }

        if (is_scalar($value) || $value instanceof Stringable) {
            $text = trim((string) $value);

            if ($text === '') {
                return [];
            }

            if (str_starts_with($text, '[') || str_starts_with($text, '{')) {
                try {
                    $decoded = json_decode($text, true, flags: JSON_THROW_ON_ERROR);
                } catch (Throwable $throwable) {
                    throw MysqlAuthDriverException::forHydration(
                        'column "' . $column . '" contains invalid JSON.',
                        $throwable,
                    );
                }

                if ($decoded === null) {
                    return [];
                }

                if (!is_array($decoded)) {
                    throw MysqlAuthDriverException::forHydration(
                        'column "' . $column . '" did not decode to a list.',
                    );
                }

                return self::normalizeList($decoded);
            }

            return self::normalizeList(explode(',', $text));
        }

        throw MysqlAuthDriverException::forHydration('column "' . $column . '" is not a list.');
    }

    /**
     * @param array<string|int, mixed> $row
     */
    private static function optionalBoolValue(array $row, ?string $column, bool $default): bool
    {
        if ($column === null || !array_key_exists($column, $row) || $row[$column] === null || $row[$column] === '') {
            return $default;
        }

        $value = $row[$column];

        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value !== 0;
        }

        if (is_string($value)) {
            return match (strtolower(trim($value))) {
                '1', 'true', 'yes', 'on', 'active', 'enabled' => true,
                '0', 'false', 'no', 'off', 'inactive', 'disabled' => false,
                default => throw MysqlAuthDriverException::forHydration(
                    'column "' . $column . '" is not a boolean.',
                ),
            };
        }

        throw MysqlAuthDriverException::forHydration('column "' . $column . '" is not a boolean.');
    }

    /**
     * @param array<string|int, mixed> $row
     */
    private static function optionalDateTimeValue(array $row, ?string $column): ?DateTimeImmutable
    {
        if ($column === null || !array_key_exists($column, $row) || $row[$column] === null || $row[$column] === '') {
            return null;
        }

        $value = $row[$column];

        if ($value instanceof DateTimeImmutable) {
            return $value;
        }

        if ($value instanceof DateTimeInterface) {
            return DateTimeImmutable::createFromInterface($value);
        }

        if (is_int($value) || (is_string($value) && preg_match('/^\d+$/', $value) === 1)) {
            return new DateTimeImmutable('@' . $value);
        }

        if (is_string($value)) {
            try {
                return new DateTimeImmutable($value);
            } catch (Throwable $throwable) {
                throw MysqlAuthDriverException::forHydration(
                    'column "' . $column . '" is not a valid date/time.',
                    $throwable,
                );
            }
        }

        throw MysqlAuthDriverException::forHydration('column "' . $column . '" is not a date/time.');
    }

    /**
     * @param array<mixed> $attributes
     * @return array<string, mixed>
     */
    private static function normalizeAttributes(array $attributes, string $column): array
    {
        $normalized = [];

        foreach ($attributes as $key => $value) {
            if (!is_string($key)) {
                throw MysqlAuthDriverException::forHydration(
                    'column "' . $column . '" must contain an object with string keys.',
                );
            }

            $key = trim($key);

            if ($key === '') {
                throw MysqlAuthDriverException::forHydration(
                    'column "' . $column . '" contains an empty attribute key.',
                );
            }

            $normalized[$key] = $value;
        }

        return $normalized;
    }

    /**
     * @param array<mixed> $values
     * @return list<string>
     */
    private static function normalizeList(array $values): array
    {
        $normalized = [];

        foreach ($values as $value) {
            if (!is_scalar($value) && !$value instanceof Stringable) {
                continue;
            }

            $value = trim((string) $value);

            if ($value !== '' && !in_array($value, $normalized, true)) {
                $normalized[] = $value;
            }
        }

        return $normalized;
    }
}
