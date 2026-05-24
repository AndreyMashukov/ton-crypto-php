<?php

declare(strict_types=1);

namespace Amashukov\TonCrypto;

use RuntimeException;

final readonly class Mnemonic
{
    public const string DEFAULT_SALT = 'TON default seed';

    public const int PBKDF2_ITERATIONS = 100_000;

    public const int PBKDF2_OUTPUT_BYTES = 64;

    public static function toSeed(string $phrase, string $password = ''): string
    {
        $normalized = self::normalize($phrase);
        $entropy    = hash_hmac('sha512', $password, $normalized, true);
        $seed64     = hash_pbkdf2(
            'sha512',
            $entropy,
            self::DEFAULT_SALT,
            self::PBKDF2_ITERATIONS,
            self::PBKDF2_OUTPUT_BYTES,
            true,
        );

        return substr($seed64, 0, KeyPair::SEED_BYTES);
    }

    public static function toKeyPair(string $phrase, string $password = ''): KeyPair
    {
        return KeyPair::fromSeed(self::toSeed($phrase, $password));
    }

    private static function normalize(string $phrase): string
    {
        $trimmed = trim($phrase);
        $single  = preg_replace('/\s+/', ' ', $trimmed);
        if (null === $single) {
            throw new RuntimeException('Mnemonic normalisation regex failed (preg internal error)');
        }

        return $single;
    }
}
