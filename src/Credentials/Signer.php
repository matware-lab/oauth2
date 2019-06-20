<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Credentials;

use Hoa\Exception\Exception;
use Psr\Log\InvalidArgumentException;
use Joomla\OAuth2\Credentials\Signer\SignerHMAC;
use Joomla\OAuth2\Credentials\Signer\Plaintext;
use Joomla\CMS\User\UserHelper;
use Joomla\OAuth2\Table\ClientsTable;
use Joomla\CMS\User\User;

/**
 * OAuth message signer interface.
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       1.0
 */
class Signer
{
	/**
	 * Method to get a message signer object based on the message's oauth_signature_method parameter.
	 *
	 * @param   string $method The method of the signer (HMAC-SHA1 || RSA-SHA1 || PLAINTEXT)
	 *
	 * @return  Signer  The OAuth message signer object for the message.
	 *
	 * @since   1.0
	 * @throws  InvalidArgumentException
	 */
	public static function getInstance($method)
	{
		switch ($method)
		{
			case 'HMAC-SHA1':
				$signer = new SignerHMAC;
				break;
			case 'RSA-SHA1':
				// @TODO We don't support RSA because we don't yet have a way to inject the private key.
				throw new InvalidArgumentException('RSA signatures are not supported');
				break;
			case 'PLAINTEXT':
				$signer = new Plaintext;
				break;
			default:
				throw new InvalidArgumentException('No valid signature method was found.');
				break;
		}

		return $signer;
	}

	/**
	 * Perform a password authentication challenge.
	 *
	 * @param   ClientsTable $client  The client object
	 * @param   object       $request The Request object.
	 *
	 * @return  boolean  True if authentication is ok, false if not
	 *
	 * @since   1.0
	 * @throws  \Exception
	 */
	public function doJoomlaAuthentication(ClientsTable $client, $request)
	{
		// Build the response for the client.
		$types = array('PHP_AUTH_', 'PHP_HTTP_', 'PHP_');

		foreach ($types as $type)
		{
			if (isset($request->_headers[$type . 'USER']))
			{
				$user_decode = base64_decode($request->_headers[$type . 'USER']);
			}

			if (isset($request->_headers[$type . 'PW']))
			{
				$password_decode = base64_decode($request->_headers[$type . 'PW']);
			}
		}

		// Check if the username and password are present
		if (!isset($user_decode) || !isset($password_decode))
		{
			if (isset($request->client_id))
			{
				$user_decode = explode(":", base64_decode($request->client_id));
				$user_decode = $user_decode[0];
			}

			if (isset($request->client_secret))
			{
				$password_decode = explode(":", base64_decode($request->client_secret));
				$password_decode = base64_decode($password_decode[1]);
				$password_decode = explode(":", $password_decode);
				$password_decode = $password_decode[0];
			}
		}

		// Check if the username and password are present
		if (!isset($user_decode) || !isset($password_decode))
		{
			throw new \Exception('Username or password is not set');
			exit;
		}

		// Verify the password
		$match = UserHelper::verifyPassword($password_decode, $client->password, $client->id);

		return $match;
	}
}
