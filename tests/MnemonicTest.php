<?php

declare(strict_types=1);

namespace Amashukov\TonCrypto\Tests;

use Amashukov\TonCrypto\KeyPair;
use Amashukov\TonCrypto\Mnemonic;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Mnemonic::class)]
final class MnemonicTest extends TestCase
{
    private const string KNOWN_24WORD_PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

    private const string EXPECTED_SEED_HEX   = '88965e4e6f686bad4be63761f4d8fa1cc682bccf11f8382bd281304d07b76edc';

    private const string EXPECTED_PUB_HEX    = 'abbd2a1c784a6086850c172bcc7d56208e4dea0a51b9389ba21d174ff864c17a';

    public function testConstantsMatchTonMnemonicSpec(): void
    {
        self::assertSame('TON default seed', Mnemonic::DEFAULT_SALT);
        self::assertSame(100_000, Mnemonic::PBKDF2_ITERATIONS);
        self::assertSame(64, Mnemonic::PBKDF2_OUTPUT_BYTES);
    }

    public function testToSeedKnownPhraseProducesExpectedSeed(): void
    {
        $seed = Mnemonic::toSeed(self::KNOWN_24WORD_PHRASE);

        self::assertSame(KeyPair::SEED_BYTES, \strlen($seed));
        self::assertSame(self::EXPECTED_SEED_HEX, bin2hex($seed));
    }

    public function testToKeyPairKnownPhraseProducesExpectedPublicKey(): void
    {
        $kp = Mnemonic::toKeyPair(self::KNOWN_24WORD_PHRASE);

        self::assertSame(self::EXPECTED_PUB_HEX, bin2hex($kp->publicKey));
    }

    public function testToSeedIsDeterministic(): void
    {
        self::assertSame(
            Mnemonic::toSeed(self::KNOWN_24WORD_PHRASE),
            Mnemonic::toSeed(self::KNOWN_24WORD_PHRASE),
        );
    }

    public function testToSeedNormalizesLeadingAndTrailingWhitespace(): void
    {
        $canonical = Mnemonic::toSeed(self::KNOWN_24WORD_PHRASE);

        self::assertSame(
            $canonical,
            Mnemonic::toSeed('   ' . self::KNOWN_24WORD_PHRASE . "\t\n"),
        );
    }

    public function testToSeedNormalizesMultipleInterWordSpaces(): void
    {
        $canonical = Mnemonic::toSeed(self::KNOWN_24WORD_PHRASE);
        $messy     = str_replace(' ', "  \t  ", self::KNOWN_24WORD_PHRASE);

        self::assertSame($canonical, Mnemonic::toSeed($messy));
    }

    public function testToSeedTreatsNewlineAsWhitespace(): void
    {
        $canonical = Mnemonic::toSeed(self::KNOWN_24WORD_PHRASE);
        $messy     = str_replace(' ', "\n", self::KNOWN_24WORD_PHRASE);

        self::assertSame($canonical, Mnemonic::toSeed($messy));
    }

    public function testPasswordChangesSeed(): void
    {
        $a = Mnemonic::toSeed(self::KNOWN_24WORD_PHRASE);
        $b = Mnemonic::toSeed(self::KNOWN_24WORD_PHRASE, 'secret');

        self::assertNotSame($a, $b);
    }

    public function testDifferentPhraseProducesDifferentSeed(): void
    {
        $a = Mnemonic::toSeed(self::KNOWN_24WORD_PHRASE);
        $b = Mnemonic::toSeed('foo bar baz');

        self::assertNotSame($a, $b);
    }

    public function testKeyPairRoundtripsThroughSignVerify(): void
    {
        $kp  = Mnemonic::toKeyPair(self::KNOWN_24WORD_PHRASE);
        $sig = $kp->sign('payload');

        self::assertTrue($kp->verify('payload', $sig));
    }
}
