<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Credentials;

use Joomla\Database\DatabaseDriver;
use Joomla\OAuth2\Protocol\Request;
use Joomla\OAuth2\Credentials\State\Initial;
use Joomla\OAuth2\Credentials\State\Authorised;
use Joomla\OAuth2\Credentials\State\Temporary;
use Joomla\OAuth2\Credentials\State\Token;
use Joomla\OAuth2\Table\CredentialsTable;
use Joomla\OAuth2\Table\ClientsTable;
use Joomla\CMS\Factory;
use Joomla\CMS\User\UserHelper;
use InvalidArgumentException;

/**
 * OAuth Credentials base class for the Joomla.Framework
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       1.0
 */
class Credentials
{
	/**
	 * @var    integer  Indicates temporary credentials.  These are ready to be authorised.
	 * @since  1.0
	 */
	const TEMPORARY = 0;

	/**
	 * @var    integer  Indicates authorised temporary credentials.  These are ready to be converted to token credentials.
	 * @since  1.0
	 */
	const AUTHORISED = 1;

	/**
	 * @var    integer  Indicates token credentials.  These are ready to be used for accessing protected resources.
	 * @since  1.0
	 */
	const TOKEN = 2;

	/**
	 * @var    Credentials  Connector object for table class.
	 * @since  1.0
	 */
	public $table;

	/**
	 * @var    State  The current credential state.
	 * @since  1.0
	 */
	public $state;

	/**
	 * @var    Request   The current HTTP Request.
	 * @since  1.0
	 */
	public $request;

	/**
	 * @var    Signer   The current credential signer.
	 * @since  1.0
	 */
	public $signer;

	/**
	 * Object constructor.
	 *
	 * @param   Request         $request  The HTTP Request
	 * @param   DatabaseDriver  $db       The database driver object. TODO: Make required
	 *
	 * @since   1.0
	 */
	public function __construct(Request $request, DatabaseDriver $db = null)
	{
		$this->request = $request;
		$this->table   = new CredentialsTable($db ?: Factory::getDbo());
		$this->state   = new Initial($this->table);
		$signature     = $this->request->signature_method ?? 'PLAINTEXT';
		$this->signer  = Signer::getInstance($signature);
	}

	/**
	 * Method to authorise the credentials.  This will persist a temporary credentials set to be authorised by
	 * a resource owner.
	 *
	 * @param   integer $resourceOwnerId The id of the resource owner authorizing the temporary credentials.
	 *
	 * @return  void
	 *
	 * @throws  \LogicException
	 * @since   1.0
	 */
	public function authorise($resourceOwnerId)
	{
		$this->state = $this->state->authorise($resourceOwnerId);
	}

	/**
	 * Method to convert a set of authorised credentials to token credentials.
	 *
	 * @return  void
	 *
	 * @throws  \LogicException
	 * @since   1.0
	 */
	public function convert()
	{
		$this->state = $this->state->convert();
	}

	/**
	 * Method to deny a set of temporary credentials.
	 *
	 * @return  void
	 *
	 * @throws  \LogicException
	 * @since   1.0
	 */
	public function deny()
	{
		$this->state = $this->state->deny();
	}

	/**
	 * Get the callback url associated with this token.
	 *
	 * @return  string
	 *
	 * @since   1.0
	 */
	public function getCallbackUrl()
	{
		return $this->state->callback_url;
	}

	/**
	 * Get the consumer key associated with this token.
	 *
	 * @return  string
	 *
	 * @since   1.0
	 */
	public function getClientId()
	{
		return $this->state->client_id;
	}

	/**
	 * Get the credentials key value.
	 *
	 * @return  string
	 *
	 * @since   1.0
	 */
	public function getClientSecret()
	{
		return $this->state->client_secret;
	}

	/**
	 * Get the temporary token secret.
	 *
	 * @return  string
	 *
	 * @since   1.0
	 */
	public function getTemporaryToken()
	{
		return $this->state->temporary_token;
	}

	/**
	 * Get the token secret.
	 *
	 * @return  string
	 *
	 * @since   1.0
	 */
	public function getAccessToken()
	{
		return $this->state->access_token;
	}

	/**
	 * Get the token secret.
	 *
	 * @return  string
	 *
	 * @since   1.0
	 */
	public function getRefreshToken()
	{
		return $this->state->refresh_token;
	}

	/**
	 * Get the ID of the user this token has been issued for.  Not all tokens
	 * will have known users.
	 *
	 * @return  integer
	 *
	 * @since   1.0
	 */
	public function getResourceOwnerId()
	{
		return $this->state->resource_owner_id;
	}

	/**
	 * Get the credentials type.
	 *
	 * @return  integer
	 *
	 * @since   1.0
	 */
	public function getType()
	{
		return (int) $this->state->type;
	}

	/**
	 * Get the expiration date.
	 *
	 * @return  integer
	 *
	 * @since   1.0
	 */
	public function getExpirationDate()
	{
		return $this->state->expiration_date;
	}

	/**
	 * Get the temporary expiration date.
	 *
	 * @return  integer
	 *
	 * @since   1.0
	 */
	public function getTemporaryExpirationDate()
	{
		return $this->state->temporary_expiration_date;
	}

	/**
	 * Method to initialise the credentials.  This will persist a temporary credentials set to be authorised by
	 * a resource owner.
	 *
	 * @param   string $clientId The key of the client requesting the temporary credentials.
	 * @param   string $url      The url being accessed in the request.
	 * @param   string $lifetime The lifetime limit of the token.
	 *
	 * @return  void
	 *
	 * @throws  \LogicException
	 * @since   1.0
	 */
	public function initialise($clientId, $url, $lifetime = 'PT4H')
	{
		$clientSecret = $this->signer->secretDecode($this->request->client_secret);

		$this->state = $this->state->initialise($clientId, $clientSecret, $url, $lifetime);
	}

	/**
	 * Perform a password authentication challenge.
	 *
	 * @param   ClientsTable $client The client.
	 *
	 * @return  boolean  True if authentication is ok, false if not
	 *
	 * @since   1.0
	 * @throws
	 */
	public function doJoomlaAuthentication(ClientsTable $client)
	{
		// Build the response for the client.
		$types = array('PHP_AUTH_', 'PHP_HTTP_', 'PHP_');

		foreach ($types as $type)
		{
			if (isset($this->request->_headers[$type . 'USER']))
			{
				$user_decode = base64_decode($this->request->_headers[$type . 'USER']);
			}

			if (isset($this->request->_headers[$type . 'PW']))
			{
				$password_decode = base64_decode($this->request->_headers[$type . 'PW']);
			}
		}

		// Check if the username and password are present
		if (!isset($user_decode) || !isset($password_decode))
		{
			if (isset($this->request->client_id))
			{
				$user_decode = explode(":", base64_decode($this->request->client_id));
				$user_decode = $user_decode[0];
			}

			if (isset($this->request->client_secret))
			{
				$password_decode = explode(":", base64_decode($this->request->client_secret));
				$password_decode = base64_decode($password_decode[1]);
				$password_decode = explode(":", $password_decode);
				$password_decode = $password_decode[0];
			}
		}

		// Check if the username and password are present
		if (!isset($user_decode) || !isset($password_decode))
		{
			throw new \Exception('Username or password is not set');
		}

		// Verify the password
		$match = UserHelper::verifyPassword($password_decode, $client->password, $client->id);

		return $match;
	}

	/**
	 * Method to load a set of credentials by key.
	 *
	 * @return  boolean
	 *
	 * @throws  InvalidArgumentException
	 * @since   1.0
	 */
	public function load()
	{
		// Initialise credentials_id
		$this->table->credentials_id = 0;

		// Load the credential
		if (isset($this->request->response_type) && !isset($this->request->access_token) && !isset($this->request->refresh_token))
		{
			// Get the correct client secret key
			$key = $this->signer->secretDecode($this->request->client_secret);

			// Load the credential using secret key
			$load = $this->table->loadBySecretKey($key, $this->request->_fetchRequestUrl());
		}
		elseif (isset($this->request->refresh_token))
		{
			// Clean all expired tokens
			$this->table->clean();

			// Load the credential using access token
			$load = $this->table->loadByRefreshToken($this->request->refresh_token, $this->request->_fetchRequestUrl());
		}
		elseif (isset($this->request->access_token))
		{
			// Clean all expired tokens
			$this->table->clean();

			// Load the credential using access token
			$load = $this->table->loadByAccessToken($this->request->access_token, $this->request->_fetchRequestUrl());
		}

		if ($load === false)
		{
			throw new InvalidArgumentException('OAuth credentials not found.');
		}

		// If nothing was found we will setup a new credential state object.
		if (!$this->table->credentials_id)
		{
			$this->state = new Initial($this->table);

			return false;
		}

		// Cast the type for validation.
		$this->table->type = (int) $this->table->type;

		// If we are loading a temporary set of credentials load that state.
		if ($this->table->type === self::TEMPORARY)
		{
			$this->state = new Temporary($this->table);
		}

		// If we are loading a authorised set of credentials load that state.
		elseif ($this->table->type === self::AUTHORISED)
		{
			$this->state = new Authorised($this->table);
		}

		// If we are loading a token set of credentials load that state.
		elseif ($this->table->type === self::TOKEN)
		{
			$this->state = new Token($this->table);
		}

		// Unknown OAuth credential type.
		else
		{
			throw new InvalidArgumentException('OAuth credentials not found.');
		}

		return true;
	}

	/**
	 * Delete expired credentials.
	 *
	 * @return  void
	 *
	 * @since   1.0
	 */
	public function clean()
	{
		$this->table->clean();
	}

	/**
	 * Method to revoke a set of token credentials.
	 *
	 * @return  void
	 *
	 * @throws  \LogicException
	 * @since   1.0
	 */
	public function revoke()
	{
		$this->state = $this->state->revoke();
	}
}
