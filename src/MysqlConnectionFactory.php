<?php

declare(strict_types=1);

namespace CommonPHP\Drivers\Authentication\MySQL;

use CommonPHP\Drivers\Authentication\MySQL\Exceptions\MysqlConnectionException;
use PDO;
use Throwable;

final readonly class MysqlConnectionFactory
{
    public function __construct(
        private MysqlDsnBuilder $dsnBuilder = new MysqlDsnBuilder(),
    ) {
    }

    /**
     * @param array<string, mixed>|MysqlConnectionOptions $options
     */
    public function connect(array|MysqlConnectionOptions $options): PDO
    {
        $options = is_array($options) ? MysqlConnectionOptions::fromArray($options) : $options;

        try {
            return new PDO(
                $this->dsnBuilder->build($options),
                $options->username(),
                $options->password(),
                $options->pdoAttributes(),
            );
        } catch (Throwable $throwable) {
            throw MysqlConnectionException::forConnection($options, $throwable);
        }
    }
}
