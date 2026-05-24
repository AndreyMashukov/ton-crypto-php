# ton-crypto-php

Ed25519 keypairs and TON-style mnemonic seed derivation for The Open Network, in pure PHP on top of `ext-sodium`.

The TON mnemonic uses PBKDF2-HMAC-SHA512 with salt `"TON default seed"` and 100 000 iterations — it is **not** BIP-39 compatible. The wordlist matches `@ton/crypto` exactly.

## Status

Pre-1.0. Public API may change before the 1.0 tag.

## Requirements

- PHP 8.3+
- `ext-sodium`

No composer dependencies.

## Credits

PHP port of [`@ton/crypto`](https://github.com/ton-org/ton-core).

## License

MIT License.
