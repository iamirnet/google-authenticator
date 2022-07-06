<?php

namespace iAmirNet\GoogleAuthenticator\Authenticator;

use iAmirNet\GoogleAuthenticator\Lib\Base32;

class Secret
{
    public static function create()
    {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // allowed characters in Base32
        $secret = '';
        for ($i = 0; $i < 16; $i++) {
            $secret .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $secret;
    }

    public static function verify($secretkey, $thistry, $relaxedmode = 'enabled', $lasttimeslot = '')
    {
        // Did the user enter 6 digits ?
        if (strlen($thistry) != 6) {
            return false;
        } else {
            $thistry = intval($thistry);
        }
        // If user is running in relaxed mode, we allow more time drifting
        // ±4 min, as opposed to ± 30 seconds in normal mode.
        if ($relaxedmode == 'enabled') {
            $firstcount = -8;
            $lastcount = 8;
        } else {
            $firstcount = -1;
            $lastcount = 1;
        }
        $tm = floor(time() / 30);

        $secretkey = Base32::decode($secretkey);
        // Keys from 30 seconds before and after are valid aswell.
        for ($i = $firstcount; $i <= $lastcount; $i++) {
            // Pack time into binary string
            $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $tm + $i);
            // Hash it with users secret key
            $hm = hash_hmac('SHA1', $time, $secretkey, true);
            // Use last nipple of result as index/offset
            $offset = ord(substr($hm, -1)) & 0x0F;
            // grab 4 bytes of the result
            $hashpart = substr($hm, $offset, 4);
            // Unpak binary value
            $value = unpack("N", $hashpart);
            $value = $value[1];
            // Only 32 bits
            $value = $value & 0x7FFFFFFF;
            $value = $value % 1000000;
            if ($value === $thistry) {
                // Check for replay (Man-in-the-middle) attack.
                // Since this is not Star Trek, time can only move forward,
                // meaning current login attempt has to be in the future compared to
                // last successful login.
                if ($lasttimeslot >= ($tm + $i)) {
                    error_log("Google Authenticator plugin: Man-in-the-middle attack detected (Could also be 2 legit login attempts within the same 30 second period)");
                    return false;
                }
                // Return timeslot in which login happened.
                return $tm + $i;
            }
        }
        return false;
    }


    public static function getUri($secret, $issuer, $label)
    {
        return "otpauth://totp/".rawurlencode($label)."?secret=".$secret."&issuer=".rawurlencode($issuer);
    }

    public static function generateQrUri($secret, $issuer, $label, $width = 200, $height = 200)
    {
        return "https://chart.googleapis.com/chart?chs={$width}x{$height}&chld=M|0&cht=qr&chl=".static::getUri($secret, $issuer, $label);
    }
}