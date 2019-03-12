<?php

namespace Beecom\Webpay;

class Signer {

  /** @var string */
  private $privateKey;

  /** @var resource */
  private $privateKeyResource;

  /** @var string */
  private $privateKeyPassword;

  /** @var string */
  private $publicKey;

  /** @var resource */
  private $publicKeyResource;

  /**
   * Signer constructor.
   *
   * @param string $privateKey
   * @param string $privateKeyPassword
   * @param string $publicKey
   */
  public function __construct (string $privateKey, string $privateKeyPassword, string $publicKey) {
    $this->privateKey = $privateKey;
    $this->privateKeyPassword = $privateKeyPassword;
    $this->publicKey = $publicKey;
  }

  /**
   * @return resource
   * @throws SignerException
   */
  private function getPrivateKeyResource () {
    if ($this->privateKeyResource) {
      return $this->privateKeyResource;
    }

    if (!($this->privateKeyResource = openssl_pkey_get_private($this->privateKey, $this->privateKeyPassword))) {
      throw new SignerException("'{$this->privateKey}' is not valid PEM private key (or passphrase is incorrect).");
    }

    return $this->privateKeyResource;
  }

  /**
   * @param array $params
   * @return string
   */
  public function sign (array $params): string {
    $digestText = implode('|', $params);
    openssl_sign($digestText, $digest, $this->getPrivateKeyResource());
    $digest = base64_encode($digest);

    return $digest;
  }

  /**
   * @param array $params
   * @param string $digest
   * @return bool
   * @throws SignerException
   */
  public function verify (array $params, $digest) {
    $data = implode('|', $params);
    $digest = base64_decode($digest);

    $ok = openssl_verify($data, $digest, $this->getPublicKeyResource());

    if ($ok !== 1) {
      throw new SignerException("Digest is not correct!");
    }

    return true;
  }

  /**
   * @return resource
   * @throws SignerException
   */
  private function getPublicKeyResource () {
    if ($this->publicKeyResource) {
      return $this->publicKeyResource;
    }

    if (!($this->publicKeyResource = openssl_pkey_get_public($this->publicKey))) {
      throw new SignerException("'{$this->publicKey}' is not valid PEM public key.");
    }

    return $this->publicKeyResource;
  }
}
