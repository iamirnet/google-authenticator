[![Latest Version](https://img.shields.io/github/release/iamirnet/google-authenticator.svg?style=flat-square)](https://github.com/iamirnet/google-authenticator/releases)
[![GitHub last commit](https://img.shields.io/github/last-commit/iamirnet/google-authenticator.svg?style=flat-square)](#)
[![Packagist Downloads](https://img.shields.io/packagist/dt/iamirnet/google-authenticator.svg?style=flat-square)](https://packagist.org/packages/iamirnet/google-authenticator)

# Google Authenticator with PHP
Google Authenticator generates 2-Step Verification codes on your phone.

2-Step Verification provides stronger security for your Google Account by requiring a second step of verification when you sign in. In addition to your password, you’ll also need a code generated by the Google Authenticator app on your phone.

Learn more about 2-Step Verification: https://g.co/2step

#### Installation
```
composer require iamirnet/google-authenticator
```
<details>
 <summary>Click for help with installation</summary>

## Install Composer
If the above step didn't work, install composer and try again.
#### Debian / Ubuntu
```
sudo apt-get install curl php-curl
curl -s http://getcomposer.org/installer | php
php composer.phar install
```
Composer not found? Use this command instead:
```
php composer.phar require "iamirnet/google-authenticator"
```

#### Installing on Windows
Download and install composer:
1. https://getcomposer.org/download/
2. Create a folder on your drive like C:\iAmirNet\GoogleAuthenticator
3. Run command prompt and type `cd C:\iAmirNet\GoogleAuthenticator`
4. ```composer require iamirnet/google-authenticator```
5. Once complete copy the vendor folder into your project.

</details>

#### Getting started
`composer require iamirnet/google-authenticator`
```php
require 'vendor/autoload.php';
// config by specifying api key and secret
$ga = new \iAmirNet\GoogleAuthenticator\Authenticator("<issuer>","<label>");
```

=======
#### Create Secret Key
```php
/**
* Create a new random secret for the Google Authenticator app.
* 16 characters, randomly chosen from the allowed Base32 characters
* equals 10 bytes = 80 bits, as 256^10 = 32^16 = 2^80
*/
print_r($ga->create($issuer = null, $label = null, $width = 200, $height = 200));
```
<details>
 <summary>View Response</summary>

```
Array
(
    'secret' => 'ILY3AYQEAPUZBUQM',
    'qr' => 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/iAmirNet?secret=ILY3AYQEAPUZBUQM&issuer=iAmirNet'
)
```
</details>

#### Verify Code
```php
//Check the verification code entered by the user.
print_r($ga->verify($secret, $pin, $relaxed = 'enabled', $last = '')); // return false or time correct
```

## Contribution
- Give us a star :star:
- Fork and Clone! Awesome
- Select existing [issues](https://github.com/iamirnet/google-authenticator/issues) or create a [new issue](https://github.com/iamirnet/google-authenticator/issues/new) and give us a PR with your bugfix or improvement after. We love it ❤️

## Donate
- USDT Or TRX: TUE8GiY4vmz831N65McwzZVbA9XEDaLinn 😘❤