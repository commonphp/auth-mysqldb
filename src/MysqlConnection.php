<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL;

use CommonPHP\Drivers\Authentication\MySQL\Exceptions\MysqlAuthDriverException;
use CommonPHP\Drivers\Authentication\MySQL\Exceptions\MysqlConnectionException;
use CommonPHP\Drivers\Authentication\MySQL\Exceptions\MysqlQueryException;
use PDO;
use PDOStatement;
use Throwable;

final class MysqlConnection
{
    private ?PDO $pdo = null;

    private ?MysqlConnectionOptions $options = null;

    /**
     * @param array<string, mixed>|MysqlConnectionOptions|PDO|null $connection
     */
    public function __construct(
        array|MysqlConnectionOptions|PDO|null $connection = null,
        private readonly MysqlConnectionFactory $connectionFactory = new MysqlConnectionFactory(),
        private readonly MysqlStatementBinder $statementBinder = new MysqlStatementBinder(),
    ) {
        if ($connection instanceof PDO) {
            $this->pdo = $connection;

            return;
        }

        $this->options = is_array($connection)
            ? MysqlConnectionOptions::fromArray($connection)
            : ($connection ?? new MysqlConnectionOptions());
    }

    public function pdo(): PDO
    {
        if ($this->pdo !== null) {
            return $this->pdo;
        }

        if ($this->options === null) {
            throw MysqlConnectionException::forInvalidOptions('MySQL auth connection options are not configured.');
        }

        return $this->pdo = $this->connectionFactory->connect($this->options);
    }

    /**
     * @param array<string|int, mixed> $parameters
     */
    public function execute(string $query, array $parameters = []): int
    {
        return $this->runStatement('execute', $query, $parameters)->rowCount();
    }

    /**
     * @param array<string|int, mixed> $parameters
     * @return array<string|int, mixed>|false
     */
    public function fetchOne(string $query, array $parameters = []): array|false
    {
        $row = $this->runStatement('fetch one', $query, $parameters)->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : false;
    }

    public function ping(): bool
    {
        try {
            $this->pdo()->query('select 1');

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @param array<string|int, mixed> $parameters
     */
    private function runStatement(string $operation, string $query, array $parameters = []): PDOStatement
    {
        try {
            $statement = $this->prepareStatement($query);
            $this->statementBinder->bind($statement, $parameters, $query);
            $statement->execute();

            return $statement;
        } catch (MysqlAuthDriverException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw MysqlQueryException::forOperation($operation, $query, $throwable);
        }
    }

    private function prepareStatement(string $query): PDOStatement
    {
        $statement = $this->pdo()->prepare($query);

        if (!$statement instanceof PDOStatement) {
            throw MysqlQueryException::forPrepareFailure($query);
        }

        return $statement;
    }
}
