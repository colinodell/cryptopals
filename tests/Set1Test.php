<?php

namespace ColinODell\Cryptopals\Test;

use ColinODell\Cryptopals\Set1;
use PHPUnit\Framework\TestCase;

class Set1Test extends TestCase
{
    public function testHex2Base64()
    {
        $this->assertEquals('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t', Set1::hex2base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'));
    }

    public function testXorBytes()
    {
        $a = hex2bin('1c0111001f010100061a024b53535009181c');
        $b = hex2bin('686974207468652062756c6c277320657965');
        $this->assertEquals(hex2bin('746865206b696420646f6e277420706c6179'), Set1::xorBytes($a, $b));

        $cipher = hex2bin('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736');
        $this->assertEquals('Cooking MC\'s like a pound of bacon', Set1::xorBytes($cipher, 'X'));
    }

    public function testDetectSingleByteXor()
    {
        $cipher = hex2bin('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736');
        [$bestKey, $score] = Set1::detectSingleByteXor($cipher);
        $this->assertEquals('X', $bestKey);
    }

    public function testDetectSingleByteXorFromArray()
    {
        $inputs = preg_split('/[\r\n]+/', file_get_contents('http://www.cryptopals.com/static/challenge-data/4.txt'));

        [$line, $bestKey] = Set1::detectSingleByteXorFromArray($inputs);

        $output = Set1::xorBytes(hex2bin($line), $bestKey);

        $this->assertEquals("15", bin2hex($bestKey));
        $this->assertEquals('7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f', $line);
        // Careful, there are some null bytes below
        $this->assertEquals('nOW THAT THE PARTY IS JUMPING*', $output);
    }

    public function testRepeatingXor()
    {
        $input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        $encrypted = Set1::xorBytes($input, 'ICE');

        $expected = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f';

        $this->assertEquals($expected, bin2hex($encrypted));
    }

    public function testHammingDistance()
    {
        $this->assertEquals(37, Set1::hammingDistance('this is a test', 'wokka wokka!!!'));
    }

    public function testTranspose()
    {
        $this->assertEquals(['abcdefg'], Set1::transpose('abcdefg', 1));
        $this->assertEquals(['aceg', 'bdf'], Set1::transpose('abcdefg', 2));
        $this->assertEquals(['adg', 'be', 'cf'], Set1::transpose('abcdefg', 3));
    }

    public function testTryToBreakRepeatingKeyXor()
    {
        $ciphertext = base64_decode(file_get_contents('http://www.cryptopals.com/static/challenge-data/6.txt'));

        $key = Set1::tryToBreakRepeatingKeyXor($ciphertext);
        $this->assertEquals(29, strlen($key));
        $this->assertEquals('TERMINATOR X BRING THE NOISE', $key);

        // Decrypt it!
        $decrypted = Set1::xorBytes($ciphertext, $key);
        $this->assertContains('sUPERCALAFRAgILISTICEXPiALiDOCIOUS', $decrypted);
    }

    public function testAES128ECBDecode()
    {
        $ciphertext = base64_decode(file_get_contents('http://www.cryptopals.com/static/challenge-data/7.txt'));

        $decrypted = Set1::decodeAES128ECB($ciphertext, 'YELLOW SUBMARINE');

        $this->assertContains('I\'m back and I\'m ringin\' the bell', $decrypted);
    }

    public function testDetectAESinECBmode()
    {
        $inputs = preg_split('/[\r\n]+/', file_get_contents('http://www.cryptopals.com/static/challenge-data/8.txt'));
        $inputs = array_map('base64_decode', $inputs);

        $result = base64_encode(Set1::detectAESinECBmode($inputs));

        $expected = 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a';
        $this->assertEquals($expected, $result);
    }
}