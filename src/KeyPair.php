<?php

declare(strict_types=1);

namespace Amashukov\TonCrypto;

use InvalidArgumentException;
use RuntimeException;

final readonly class KeyPair
{
    public const int SEED_BYTES       = SODIUM_CRYPTO_SIGN_SEEDBYTES;

    public const int PUBLIC_KEY_BYTES = SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;

    public const int SECRET_KEY_BYTES = SODIUM_CRYPTO_SIGN_SECRETKEYBYTES;

    public const int SIGNATURE_BYTES  = SODIUM_CRYPTO_SIGN_BYTES;

    /**
     * @param non-empty-string $publicKey
     * @param non-empty-string $secretKey
     */
    private function __construct(
        public string $publicKey,
        public string $secretKey,
    ) {}

    public static function fromSeed(string $seed): self
    {
        if (self::SEED_BYTES !== \strlen($seed)) {
            throw new InvalidArgumentException(sprintf('KeyPair seed must be %d bytes, got %d', self::SEED_BYTES, \strlen($seed)));
        }

        $bundle    = sodium_crypto_sign_seed_keypair($seed);
        $publicKey = sodium_crypto_sign_publickey($bundle);
        $secretKey = sodium_crypto_sign_secretkey($bundle);
        if (self::PUBLIC_KEY_BYTES !== \strlen($publicKey)) {
            throw new RuntimeException(sprintf('libsodium publickey size mismatch: expected %d bytes', self::PUBLIC_KEY_BYTES));
        }
        if (self::SECRET_KEY_BYTES !== \strlen($secretKey)) {
            throw new RuntimeException(sprintf('libsodium secretkey size mismatch: expected %d bytes', self::SECRET_KEY_BYTES));
        }

        return new self($publicKey, $secretKey);
    }

    public static function generate(): self
    {
        return self::fromSeed(random_bytes(self::SEED_BYTES));
    }

    public function sign(string $message): string
    {
        return sodium_crypto_sign_detached($message, $this->secretKey);
    }

    public function verify(string $message, string $signature): bool
    {
        if (self::SIGNATURE_BYTES !== \strlen($signature)) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $message, $this->publicKey);
    }
}
