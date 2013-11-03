# GP Webpay PHP API
[![Build Status](https://travis-ci.org/newPOPE/webpay-php.png?branch=dev/2.0.0)](https://travis-ci.org/newPOPE/webpay-php)

Full featured PHP API wrapper for GP Webpay payments.

### Actual code is under development now.


### Setup

```php

    $signer = new \Webpay\Signer(
        $privateKeyFilepath,    // Path of private key.
        $privateKeyPassword,    // Password for private key.
        $publicKeyFilepath      // Path of public key.
    );
    
    $api = new \Webpay\Api(
        $merchantNumber,    // Merchant number.
        $webpayUrl,         // URL of webpay.
        $signer             // instance of \Webpay\Signer.
    );
```

Sponsored by [ham.sk](http://www.ham.sk).
