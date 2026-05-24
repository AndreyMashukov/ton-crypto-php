# ton-crypto-php

Ed25519 keypairs and TON-style mnemonic seed derivation for The Open Network, in pure PHP on top of `ext-sodium`.

The TON mnemonic format uses PBKDF2-HMAC-SHA512 with salt `"TON default seed"` and 100 000 iterations — it is **not** BIP-39 compatible. The wordlist and derivation procedure mirror the TON reference implementation, so the same 24-word phrase produces the same Ed25519 keypair across TON tooling.

## Install

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

## Layout of `KeyPair`

- `KeyPair::SEED_BYTES` = 32 (libsodium `SODIUM_CRYPTO_SIGN_SEEDBYTES`)
- `KeyPair::PUBLIC_KEY_BYTES` = 32
- `KeyPair::SECRET_KEY_BYTES` = 64 (libsodium layout: `seed ‖ publicKey`)
- `KeyPair::SIGNATURE_BYTES` = 64

## TON mnemonic parameters

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

## Reference

- TON Mnemonic specification: <https://docs.ton.org/develop/dapps/asset-processing/cookbook#how-to-generate-keypair-from-mnemonic-and-sign-arbitrary-data>
- Ed25519 specification (RFC 8032): <https://www.rfc-editor.org/rfc/rfc8032>

## License

MIT License.
