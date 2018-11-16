<?php declare(strict_types = 1);

namespace ColinODell\Cryptopals;

class Set2
{
    public static function addPKCS7Padding(string $input, int $blockSize): string
    {
        $expectedSize = (int)ceil(strlen($input) / $blockSize) * $blockSize;
        $missing = $expectedSize - strlen($input);

        return $input . str_repeat(chr($missing), $missing);
    }
}
