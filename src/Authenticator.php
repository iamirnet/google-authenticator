<?php
namespace iAmirNet\GoogleAuthenticator;

use iAmirNet\GoogleAuthenticator\Authenticator\Secret;

class Authenticator
{
    public $issuer, $label, $secret;

    public function __construct($issuer = null, $label = null, $secret = null)
    {
        $this->issuer = $issuer;
        $this->label = $label;
        $this->secret = $secret;
    }

    public function create($issuer = null, $label = null, $width = 200, $height = 200) {
        $this->secret = Secret::create();
        if ($issuer) $this->issuer = $issuer;
        if ($label) $this->label = $label;
        $qr_image = Secret::generateQrUri($this->secret, $this->issuer, $this->label, $width, $height);
        return ['secret' => $this->secret, 'qr' => $qr_image];
    }

    public static function created($issuer = null, $label = null, $width = 200, $height = 200) {
        return (new self)->create($issuer, $label, $width, $height);
    }

    public function verify($secret, $pin, $relaxed = 'enabled', $last = '') {
        return Secret::verify($secret ? : $this->secret, $pin, $relaxed, $last);
    }

    public static function verified($secret, $pin, $relaxed = 'enabled', $last = '') {
        return Secret::verify($secret, $pin, $relaxed, $last);
    }

}