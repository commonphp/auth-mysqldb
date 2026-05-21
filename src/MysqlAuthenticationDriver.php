<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\Contracts\AbstractAuthenticationDriver;
use CommonPHP\Authentication\Contracts\CredentialInterface;
use CommonPHP\Drivers\Authentication\MySQL\Exceptions\MysqlAuthDriverException;
use PDO;
use Throwable;

final class MysqlAuthenticationDriver extends AbstractAuthenticationDriver
{
    private MysqlConnection $connection;

    private MysqlAuthOptions $options;

    private PasswordVerifier $passwordVerifier;

    private MysqlUserMapper $userMapper;

    /**
     * @param array<string, mixed>|MysqlConnectionOptions|MysqlConnection|PDO|null $connection
     * @param array<string, mixed>|MysqlAuthOptions|null $options
     */
    public function __construct(
        array|MysqlConnectionOptions|MysqlConnection|PDO|null $connection = null,
        array|MysqlAuthOptions|null $options = null,
        ?PasswordVerifier $passwordVerifier = null,
        ?MysqlUserMapper $userMapper = null,
    ) {
        $this->connection = $connection instanceof MysqlConnection
            ? $connection
            : new MysqlConnection($connection);
        $this->options = is_array($options)
            ? MysqlAuthOptions::fromArray($options)
            : ($options ?? new MysqlAuthOptions());
        $this->passwordVerifier = $passwordVerifier ?? new PasswordVerifier();
        $this->userMapper = $userMapper ?? new MysqlUserMapper();
    }

    public function getName(): string
    {
        return 'mysql-auth';
    }

    public function connection(): MysqlConnection
    {
        return $this->connection;
    }

    public function options(): MysqlAuthOptions
    {
        return $this->options;
    }

    public function passwordVerifier(): PasswordVerifier
    {
        return $this->passwordVerifier;
    }

    public function userMapper(): MysqlUserMapper
    {
        return $this->userMapper;
    }

    public function supports(CredentialInterface $credentials): bool
    {
        return $credentials->hasSecret();
    }

    public function authenticate(CredentialInterface $credentials): AuthenticationResult
    {
        if (!$credentials->hasSecret()) {
            return $this->invalidCredentials('MySQL authentication requires a secret.');
        }

        $record = $this->findRecord($credentials->identifier());

        if ($record === null) {
            return $this->identityNotFound($credentials->identifier());
        }

        if (!$record->active) {
            return $this->failed('Identity is inactive.', ['identifier' => $record->identifier]);
        }

        if ($record->locked) {
            return AuthenticationResult::locked('Identity is locked.', ['identifier' => $record->identifier]);
        }

        if ($record->credentialsExpired()) {
            return AuthenticationResult::expired('Credentials are expired.', ['identifier' => $record->identifier]);
        }

        if (!$this->passwordVerifier->verify((string) $credentials->secret(), $record->passwordHash)) {
            return $this->invalidCredentials('Invalid MySQL credentials.', [
                'identifier' => $record->identifier,
            ]);
        }

        return $this->authenticated(
            $this->userMapper->identity($record),
            'Authenticated by MySQL.',
            [
                'driver' => $this->getName(),
                'identifier' => $record->identifier,
            ],
        );
    }

    private function findRecord(string $identifier): ?MysqlUserRecord
    {
        try {
            $row = $this->connection->fetchOne(
                $this->options->selectSql(),
                $this->options->lookupParameters($identifier),
            );
        } catch (MysqlAuthDriverException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw MysqlAuthDriverException::forLookup($identifier, $throwable);
        }

        if ($row === false) {
            return null;
        }

        return MysqlUserRecord::fromRow($row, $this->options);
    }
}
