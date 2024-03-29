<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Credentials\Signer;

use Joomla\OAuth2\Credentials\Signer;
use PHPUnit\Runner\Exception;

/**
 * OAuth RSA-SHA1 Signature Method class.
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       1.0
 */
class SignerRSA implements Signer
{
	/**
	 * @var    string  Either a PEM formatted private key or a string having the format file://path/to/file.pem. The named file must contain
	 *                 a PEM encoded certificate/private key (it may contain both).
	 * @see    openssl_pkey_get_private
	 * @since  1.0
	 */
	private $_pem;

	/**
	 * @var    string  The optional parameter passphrase must be used if the specified key is encrypted (protected by a passphrase).
	 * @see    openssl_pkey_get_private
	 * @since  1.0
	 */
	private $_passphrase;

	/**
	 * Object constructor.
	 *
	 * @param   string  $pem         The private key PEM string or file location.
	 * @param   string  $passphrase  The private key passphrase if specified.
	 *
	 * @codeCoverageIgnore
	 * @see     openssl_pkey_get_private
	 * @since   1.0
	 */
	public function __construct($pem, $passphrase = null)
	{
		$this->_pem = $pem;
		$this->_passphrase = $passphrase;
	}

	/**
	 * Calculate and return the OAuth message signature using RSA-SHA1
	 *
	 * @param   string  $baseString        The OAuth message as a normalized base string.
	 * @param   string  $clientSecret      The OAuth client's secret.
	 * @param   string  $credentialSecret  The OAuth credentials' secret.
	 *
	 * @return  string  The OAuth message signature.
	 *
	 * @since   1.0
	 * @throws  InvalidArgumentException
	 */
	public function sign($baseString, $clientSecret, $credentialSecret)
	{
		// Initialise variables.
		$signature = null;

		// Load a private key resource from a certificate.
		$privateKey = openssl_pkey_get_private($this->_pem, $this->_passphrase);

		if (!$privateKey)
		{
			throw new RuntimeException('Unable to get the private key resource.');
		}

		// Sign the string using our private key resource.
		$success = openssl_sign($baseString, $signature, $privateKey);

		if (!$success)
		{
			throw new RuntimeException('Unable to generate the signature.');
		}

		// Let's clean up after ourselves.
		openssl_free_key($privateKey);

		return base64_encode($signature);
	}
}
