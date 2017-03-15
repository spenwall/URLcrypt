<?php

/**
 * URLCrypt
 *
 * PHP library to securely encode and decode short pieces of arbitrary binary data in URLs.
 *
 * (c) Guillermo Gonzalez
 *
 * For the full copyright and license information, please view the COPYING
 * file that was distributed with this source code.
 */

namespace UrlCrypt;

class UrlCrypt
{
    public static $table = "1bcd2fgh3jklmn4pqrstAvwxyz567890";
    protected static $cipher = MCRYPT_RIJNDAEL_128;
    protected static $mode = MCRYPT_MODE_CBC;

    public static function encode($string)
    {
        $n = strlen($string) * 8 / 5;
        $arr = str_split($string, 1);

        $m = "";
        foreach ($arr as $c) {
            $m .= str_pad(decbin(ord($c)), 8, "0", STR_PAD_LEFT);
        }

        $p = ceil(strlen($m) / 5) * 5;

        $m = str_pad($m, $p, "0", STR_PAD_RIGHT);

        $newstr = "";
        for ($i = 0; $i < $n; $i++) {
            $newstr .= self::$table[bindec(substr($m, $i * 5, 5))];
        }

        return $newstr;
    }

    public static function decode($string)
    {
        $n = strlen($string) * 5 / 8;
        $arr = str_split($string, 1);

        $m = "";
        foreach ($arr as $c) {
            $m .= str_pad(decbin(array_search($c, self::$table)), 5, "0", STR_PAD_LEFT);
        }

        $oldstr = "";
        for ($i = 0; $i < floor($n); $i++) {
            $oldstr .= chr(bindec(substr($m, $i * 8, 8)));
        }

        return $oldstr;
    }

    /**
     * @param string $string
     * @param string $key
     * @return string
     * @throws \Exception
     */
    public static function encrypt($string, $key)
    {
        if (is_null($key) || $key == "") {
            throw new \Exception('No key provided.');
        }

        $key = pack('H*', $key);

        $iv_size = mcrypt_get_iv_size(self::$cipher, self::$mode);

        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        $string = utf8_encode($string);

        $ciphertext = mcrypt_encrypt(self::$cipher, $key, $string, self::$mode, $iv);

        $ciphertext = $iv . $ciphertext;

        return self::encode($ciphertext);
    }

    public static function decrypt($string, $key)
    {
        if ($key === "") {
            throw new \Exception('No key provided.');
        }

        $key = pack('H*', $key);

        $string = self::decode($string);

        $iv_size = mcrypt_get_iv_size(self::$cipher, self::$mode);
        $iv_dec = substr($string, 0, $iv_size);

        $string = substr($string, $iv_size);

        $string = mcrypt_decrypt(self::$cipher, $key, $string, self::$mode, $iv_dec);

        return rtrim($string, "\0");
    }
}

Urlcrypt::$table = str_split(Urlcrypt::$table, 1);
