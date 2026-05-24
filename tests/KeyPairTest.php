<?php

declare(strict_types=1);

namespace Amashukov\TonCrypto\Tests;

use Amashukov\TonCrypto\KeyPair;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(KeyPair::class)]
final class KeyPairTest extends TestCase
{
    private const string KNOWN_SEED_HEX = '88965e4e6f686bad4be63761f4d8fa1cc682bccf11f8382bd281304d07b76edc';

    private const string KNOWN_PUB_HEX  = 'abbd2a1c784a6086850c172bcc7d56208e4dea0a51b9389ba21d174ff864c17a';

    public function testConstantsMatchLibsodiumEd25519Sizes(): void
    {
        self::assertSame(32, KeyPair::SEED_BYTES);
        self::assertSame(32, KeyPair::PUBLIC_KEY_BYTES);
        self::assertSame(64, KeyPair::SECRET_KEY_BYTES);
        self::assertSame(64, KeyPair::SIGNATURE_BYTES);
    }

    public function testFromSeedProducesKnownPublicKey(): void
    {
        $kp = KeyPair::fromSeed($this->bin(self::KNOWN_SEED_HEX));

        self::assertSame(self::KNOWN_PUB_HEX, bin2hex($kp->publicKey));
    }

    public function testFromSeedSecretKeyShapeIsSeedConcatPublicKey(): void
    {
        $seed = $this->bin(self::KNOWN_SEED_HEX);
        $kp   = KeyPair::fromSeed($seed);

        self::assertSame($seed . $kp->publicKey, $kp->secretKey);
        self::assertSame(64, \strlen($kp->secretKey));
    }

    public function testFromSeedRejectsShortSeed(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('seed must be 32 bytes');

        KeyPair::fromSeed(str_repeat("\x00", 31));
    }

    public function testFromSeedRejectsLongSeed(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('seed must be 32 bytes');

        KeyPair::fromSeed(str_repeat("\x00", 33));
    }

    public function testGenerateProducesValidKeypair(): void
    {
        $kp = KeyPair::generate();

        self::assertSame(32, \strlen($kp->publicKey));
        self::assertSame(64, \strlen($kp->secretKey));
    }

    public function testGenerateReturnsDistinctKeypairs(): void
    {
        $a = KeyPair::generate();
        $b = KeyPair::generate();

        self::assertNotSame($a->publicKey, $b->publicKey);
        self::assertNotSame($a->secretKey, $b->secretKey);
    }

    public function testSignProducesSixtyFourByteSignature(): void
    {
        $kp  = KeyPair::fromSeed($this->bin(self::KNOWN_SEED_HEX));
        $sig = $kp->sign('hello');

        self::assertSame(64, \strlen($sig));
    }

    public function testSignIsDeterministicForIdenticalInput(): void
    {
        $kp = KeyPair::fromSeed($this->bin(self::KNOWN_SEED_HEX));

        self::assertSame($kp->sign('hello'), $kp->sign('hello'));
    }

    public function testVerifyAcceptsOwnSignature(): void
    {
        $kp  = KeyPair::generate();
        $sig = $kp->sign('payload');

        self::assertTrue($kp->verify('payload', $sig));
    }

    public function testVerifyRejectsTamperedMessage(): void
    {
        $kp  = KeyPair::generate();
        $sig = $kp->sign('payload');

        self::assertFalse($kp->verify('payloaD', $sig));
    }

    public function testVerifyRejectsTamperedSignature(): void
    {
        $kp  = KeyPair::generate();
        $sig = $kp->sign('payload');
        $bad = $sig;
        $bad[0] = \chr((\ord($sig[0]) ^ 0x01) & 0xFF);

        self::assertFalse($kp->verify('payload', $bad));
    }

    public function testVerifyRejectsWrongLengthSignature(): void
    {
        $kp = KeyPair::generate();

        self::assertFalse($kp->verify('payload', str_repeat("\x00", 63)));
        self::assertFalse($kp->verify('payload', str_repeat("\x00", 65)));
    }

    public function testVerifyRejectsSignatureFromDifferentKey(): void
    {
        $kpA = KeyPair::generate();
        $kpB = KeyPair::generate();
        $sig = $kpA->sign('payload');

        self::assertFalse($kpB->verify('payload', $sig));
    }

    private function bin(string $hex): string
    {
        $out = hex2bin($hex);
        if (false === $out) {
            self::fail('test fixture hex must decode: ' . $hex);
        }

        return $out;
    }
}
