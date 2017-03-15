<?php

namespace Test\Atrapalo\UrlCrypt;

use Atrapalo\UrlCrypt\UrlCrypt;

class UrlCryptTest extends \PHPUnit_Framework_TestCase
{
    /** @var UrlCrypt */
    private $urlCrypt;
    
    protected function setUp()
    {
        $this->urlCrypt = new UrlCrypt();
    }

    /**
     * @test
     * Test 300 strings of random characters for each length between 1 and 30.
     */
    public function arbitraryEncode()
    {
        for ($i = 1; $i < 31; $i++) {
            for ($n = 0; $n < 300; $n++) {
                $string = '';
                for ($z = 0; $z < $i; $z++) {
                    $string .= chr(rand(0, 255));
                }
                $decodeString = $this->encodeAndDecode($string);

                $this->assertEquals($string, $decodeString);
            }
        }
    }

    /**
     * @test
     */
    public function emptyString()
    {
        $decodeString = $this->encodeAndDecode('');

        $this->assertEmpty($decodeString);
    }

    /**
     * @test
     */
    public function definedEncode()
    {
        $this->assertEquals('mnAhk6tlp2qg2yldn8xcc', $this->urlCrypt->encode('chunky bacon!'));
    }

    /**
     * @test
     */
    public function definedDecode()
    {
        $this->assertEquals('chunky bacon!', $this->urlCrypt->decode('mnAhk6tlp2qg2yldn8xcc'));
    }

    /**
     * @test
     * @expectedException \Exception
     */
    public function nullKey()
    {
        $this->urlCrypt->encrypt('Atrapalo', null);
    }

    /**
     * @test
     * @expectedException \Exception
     */
    public function emptyKey()
    {
        $this->urlCrypt->encrypt('Atrapalo', '');
    }

    /**
     * @test
     */
    public function encryption()
    {
        $string = 'Atrapalo';
        $key = 'bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3';
        $encrypted = $this->urlCrypt->encrypt($string, $key);
        $decrypted = $this->urlCrypt->decrypt($encrypted, $key);

        $this->assertEquals($string, $decrypted);
    }

    /**
     * @test
     */
    public function failEncryptionWhitDifferentKeys()
    {
        $string = 'Atrapalo';

        $key = 'bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3';
        $encrypted = $this->urlCrypt->encrypt($string, $key);

        $key2 = 'c55abe029fdebae5e1d417e2ffb2a00a3bcb04b7e103a0cd8b54763051cef08b';
        $decrypted = $this->urlCrypt->decrypt($encrypted, $key2);

        $this->assertNotEquals($string, $decrypted);
    }

    /**
     * @param string $string
     * @return string
     */
    private function encodeAndDecode($string)
    {
        return $this->urlCrypt->decode($this->urlCrypt->encode($string));
    }
}
