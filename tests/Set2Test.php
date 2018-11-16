<?php declare(strict_types = 1);

namespace ColinODell\Cryptopals\Test;

use ColinODell\Cryptopals\Set2;
use PHPUnit\Framework\TestCase;

class Set2Test extends TestCase
{
    public function testAddPKCS7Padding()
    {
        $this->assertRegExp('/^foo$/', Set2::addPKCS7Padding('foo', 1));
        $this->assertRegExp('/^foo\x01$/', Set2::addPKCS7Padding('foo', 2));
        $this->assertRegExp('/^foo$/', Set2::addPKCS7Padding('foo', 3));
        $this->assertRegExp('/^foo\x01$/', Set2::addPKCS7Padding('foo', 4));
        $this->assertRegExp('/^foo\x02\x02$/', Set2::addPKCS7Padding('foo', 5));
        $this->assertRegExp('/^foo\x03\x03\x03$/', Set2::addPKCS7Padding('foo', 6));
    }
}
