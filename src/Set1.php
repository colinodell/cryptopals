<?php declare(strict_types = 1);

namespace ColinODell\Cryptopals;

final class Set1
{
    public static function hex2base64(string $input): string
    {
        $raw = hex2bin($input);

        return base64_encode($raw);
    }

    public static function xorBytes(string $a, string $b): string
    {
        // Pad the key
        $key = '';
        while (strlen($key) < strlen($a)) {
            $key .= $b;
        }

        $arrayA = str_split($a);
        $arrayKey = str_split($key);

        $result = '';
        foreach ($arrayA as $i => $val) {
            $result .= $val ^ $arrayKey[$i];
        }

        return $result;
    }

    public static function score(string $possibleText): int
    {
        $englishScores = str_split('zqjxkvbpgyfwmculdrhsnioate');

        $score = 0;
        foreach (str_split($possibleText) as $possibleChar) {
            $possibleChar = strtolower($possibleChar);
            $score += array_search($possibleChar, $englishScores) ?: 0;
        }

        return $score;
    }

    public static function detectSingleByteXor(string $cipher)
    {
        $highestScore = 0;
        $highestScoreKey = null;

        for ($i = 0; $i < 256; $i++) {
            $xored = self::xorBytes($cipher, chr($i));
            $score = self::score($xored);

            if ($score > $highestScore) {
                $highestScore = $score;
                $highestScoreKey = $i;
            }
        }

        return [chr($highestScoreKey), $highestScore];
    }

    public static function detectSingleByteXorFromArray(array $strings)
    {
        $bestScore = 0;
        $bestScoreLine = null;
        $bestKey = null;
        foreach ($strings as $i => $line) {
            [$key, $score] = self::detectSingleByteXor(hex2bin($line));

            if ($score > $bestScore) {
                $bestScore = $score;
                $bestKey = $key;
                $bestScoreLine = $line;
            }
        }

        return [$bestScoreLine, $bestKey];
    }

    public static function hammingDistance(string $a, string $b): int
    {
        $count = 0;
        foreach (unpack('C*', $a ^ $b) as $diff) {
            while ($diff) {
                $diff &= $diff - 1;
                $count++;
            }
        }
        return $count;
    }

    public static function transpose(string $input, int $keySize): array
    {
        $ret = [];
        $i = 0;

        foreach (str_split($input) as $char) {
            @$ret[$i++ % $keySize] .= $char;
        }

        return $ret;
    }

    public static function guessKeySize(string $input, int $minSize = 2, int $maxSize = 40): int
    {
        $scoreByKeysize = [];

        for ($keysize = $minSize; $keysize <= $maxSize; $keysize++) {
            $distance = 0;

            $firstLittleBit = substr($input, 0, $keysize);
            $blocksToTest = floor(strlen($input) / $maxSize);

            for ($i = 1; $i < $blocksToTest; $i++) {
                $nextLittleBit = substr($input, $keysize * $i,  $keysize * $i);
                $distance += self::hammingDistance($firstLittleBit, $nextLittleBit);
            }

            $normalizedDistance = $distance / $keysize;

            $scoreByKeysize[$keysize] = $normalizedDistance;
        }

        asort($scoreByKeysize);

        return key($scoreByKeysize);
    }

    public static function tryToBreakRepeatingKeyXor(string $input, ?int $keySize = null)
    {
        if (!$keySize) {
            $keySize = self::guessKeySize($input);
        }

        $transposed = self::transpose($input, $keySize);

        $fullKey = '';
        foreach ($transposed as $block) {
            [$key, $score] = self::detectSingleByteXor($block);
            $fullKey .= $key;
        }

        return $fullKey;
    }

    public static function decodeAES128ECB(string $ciphertext, string $key): string
    {
        return openssl_decrypt($ciphertext, 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
    }

    public static function detectAESinECBmode(array $inputs): string
    {
        $duplicateBlocks = [];
        foreach ($inputs as $input) {
            $blockCounts = [];

            // Chunk the cipher into 16-byte blocks and count unique instances of these blocks
            foreach (str_split($input, 16) as $block) {
                @$blockCounts[$block]++;
            }

            // Score them by summing the number of duplicate blocks found
            $blockCounts = array_filter($blockCounts, function($count) { return $count > 1; });
            $duplicateBlocks[$input] = array_sum($blockCounts);
        }

        // Find and return the index with the highest score
        arsort($duplicateBlocks);

        return key($duplicateBlocks);
    }
}