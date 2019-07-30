<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Credentials;

use Joomla\OAuth2\Credentials\Signer\Hmac;
use Joomla\OAuth2\Credentials\Signer\Plaintext;

/**
 * OAuth message signer interface.
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       1.0
 */
abstract class Signer implements SignerInterface
{
	/**
	 * Method to get a message signer object based on the message's oauth_signature_method parameter.
	 *
	 * @param   string $method The method of the signer (HMAC-SHA1 || RSA-SHA1 || PLAINTEXT)
	 *
	 * @return  Signer  The OAuth message signer object for the message.
	 *
	 * @since   1.0
	 * @throws  \InvalidArgumentException
	 */
	public static function getInstance($method)
	{
		switch ($method)
		{
			case 'HMAC-SHA1':
				$signer = new Hmac;
				break;
			case 'RSA-SHA1':
				// @TODO We don't support RSA because we don't yet have a way to inject the private key.
				throw new \InvalidArgumentException('RSA signatures are not supported');
				break;
			case 'PLAINTEXT':
				$signer = new Plaintext;
				break;
			default:
				throw new \InvalidArgumentException('No valid signature method was found.');
				break;
		}

		return $signer;
	}
}
