# amashukov/ton-crypto-php

Correct TON mnemonic + Ed25519 keypair derivation for The Open Network in pure PHP.

[![CI](https://img.shields.io/github/actions/workflow/status/AndreyMashukov/ton-crypto-php/ci.yml?branch=main&label=CI)](https://github.com/AndreyMashukov/ton-crypto-php/actions)
[![PHPStan L9](https://img.shields.io/github/actions/workflow/status/AndreyMashukov/ton-crypto-php/stan.yml?branch=main&label=PHPStan%20L9)](https://github.com/AndreyMashukov/ton-crypto-php/actions)
[![Latest Version](https://img.shields.io/packagist/v/amashukov/ton-crypto-php)](https://packagist.org/packages/amashukov/ton-crypto-php)
[![Downloads](https://img.shields.io/packagist/dt/amashukov/ton-crypto-php)](https://packagist.org/packages/amashukov/ton-crypto-php)
[![PHP](https://img.shields.io/packagist/dependency-v/amashukov/ton-crypto-php/php)](https://packagist.org/packages/amashukov/ton-crypto-php)
[![License](https://img.shields.io/packagist/l/amashukov/ton-crypto-php)](LICENSE)
[![Stars](https://img.shields.io/github/stars/AndreyMashukov/ton-crypto-php?style=social)](https://github.com/AndreyMashukov/ton-crypto-php)

TON cryptography for PHP: Ed25519 keypairs (sign / verify via libsodium) and **TON-flavoured mnemonic seed derivation** for The Open Network. The TON mnemonic format is PBKDF2-HMAC-SHA512 with salt `"TON default seed"` and 100 000 iterations — it is **not** BIP-39. The wordlist and derivation procedure mirror the TON reference implementation, so the same 24-word phrase produces the same Ed25519 keypair (and therefore the same wallet address) across all TON tooling.

## Features

- TON-correct mnemonic → seed → Ed25519 keypair derivation (PBKDF2-HMAC-SHA512, salt `"TON default seed"`, 100 000 iterations).
- Ed25519 keypair generation, sign and verify on top of `ext-sodium`.
- Deterministic phrase normalisation (trims, collapses tab/newline/whitespace runs to a single space).
- Optional password passthrough on the HMAC step.
- Zero composer dependencies — only PHP core extensions.
- PHPStan level 9 clean, `final readonly` value objects, `strict_types`.

## Why amashukov/ton-crypto-php

BIP-39 mnemonic libraries derive the **wrong** key for TON. TON does not use the BIP-39 PBKDF2 salt (`"mnemonic"`) or iteration scheme — it uses a distinct entropy → seed pipeline (`hash_hmac` pass feeding PBKDF2-HMAC-SHA512 with salt `"TON default seed"`, 100 000 iterations). Feeding a TON phrase to a generic BIP-39 library yields a seed and address that do not match TON wallets. This package implements the TON procedure exactly, so derived addresses match official TON tooling byte-for-byte.

## Installation

```bash
composer require amashukov/ton-crypto-php
```

## Usage

### Derive a keypair from a mnemonic phrase

```php
use Amashukov\TonCrypto\Mnemonic;

$phrase  = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
$keypair = Mnemonic::toKeyPair($phrase);

// Or just the raw 32-byte seed:
$seed = Mnemonic::toSeed($phrase);
```

`toSeed()` and `toKeyPair()` normalise the phrase (trims leading/trailing whitespace, collapses any inter-word run of whitespace — including tabs and newlines — to a single space). Both accept an optional `$password` argument that is fed through the HMAC step.

### Generate a fresh keypair

```php
use Amashukov\TonCrypto\KeyPair;

$kp = KeyPair::generate();           // 32-byte seed from random_bytes()
$kp = KeyPair::fromSeed($seedBytes); // explicit 32-byte seed
```

### Sign + verify

```php
$signature = $kp->sign('payload');           // 64 raw bytes (Ed25519 detached)
$ok        = $kp->verify('payload', $signature);
```

`verify()` returns `false` for any signature whose length is not exactly 64 bytes, in addition to the cryptographic check.

### `KeyPair` layout

- `KeyPair::SEED_BYTES` = 32 (libsodium `SODIUM_CRYPTO_SIGN_SEEDBYTES`)
- `KeyPair::PUBLIC_KEY_BYTES` = 32
- `KeyPair::SECRET_KEY_BYTES` = 64 (libsodium layout: `seed ‖ publicKey`)
- `KeyPair::SIGNATURE_BYTES` = 64

### TON mnemonic parameters

- Salt: `TON default seed`
- KDF: PBKDF2-HMAC-SHA512
- Iterations: 100 000
- Output: 64 bytes; first 32 bytes are the Ed25519 seed
- HMAC pass: `hash_hmac('sha512', $password, $normalizedPhrase, true)` produces the entropy fed into PBKDF2

These constants are exposed on `Mnemonic::DEFAULT_SALT`, `Mnemonic::PBKDF2_ITERATIONS`, `Mnemonic::PBKDF2_OUTPUT_BYTES`.

## Requirements

- PHP 8.3+
- `ext-sodium`
- `ext-hash` (bundled with PHP core; used for HMAC-SHA512 + PBKDF2)

No composer dependencies.

## Related packages

| Package | Tier | Purpose |
|---|---|---|
| [amashukov/ton-cell-php](https://github.com/AndreyMashukov/ton-cell-php) | leaf | TLB Cell / BoC serialization |
| [amashukov/ton-wallet-php](https://github.com/AndreyMashukov/ton-wallet-php) | composite | TON wallet contracts + address derivation |
| [amashukov/toncenter-client-php](https://github.com/AndreyMashukov/toncenter-client-php) | RPC | toncenter v2/v3 API client |
| [amashukov/ton-php](https://github.com/AndreyMashukov/ton-php) | meta | TON umbrella package |
| [amashukov/keccak-php](https://github.com/AndreyMashukov/keccak-php) | leaf | keccak-256 hashing |

## Quality

- PHPStan level 9.
- php-cs-fixer with the `@PER-CS` ruleset.
- GitHub Actions CI on every push.
- Derived seeds and addresses validated against the TON reference implementation.

## License

MIT.
