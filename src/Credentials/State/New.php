<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */



namespace Joomla\OAuth2\Credentials\State;

use Joomla\OAuth2\Credentials\State;
use Joomla\OAuth2\Credentials\Credentials;
use Joomla\OAuth2\Credentials\State\Temporary;
use LogicException;

/**
 * OAuth New Credentials class for the Matware.Libraries
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       1.0
 */
class New extends State
{
	/**
	 * Method to authorise the credentials.  This will persist a temporary credentials set to be authorised by
	 * a resource owner.
	 *
	 * @param   integer  $resourceOwnerId  The id of the resource owner authorizing the temporary credentials.
	 * @param   integer  $lifetime         How long the permanent credentials should be valid (defaults to forever).
	 *
	 * @return  void
	 *
	 * @since   1.0
	 * @throws  LogicException
	 */
	public function authorise($resourceOwnerId, $lifetime = 0)
	{
		throw new LogicException('Only temporary credentials can be authorised.');
	}

	/**
	 * Method to convert a set of authorised credentials to token credentials.
	 *
	 * @return  void
	 *
	 * @since   1.0
	 * @throws  LogicException
	 */
	public function convert()
	{
		throw new LogicException('Only authorised credentials can be converted.');
	}

	/**
	 * Method to deny a set of temporary credentials.
	 *
	 * @return  void
	 *
	 * @since   1.0
	 * @throws  LogicException
	 */
	public function deny()
	{
		throw new LogicException('Only temporary credentials can be denied.');
	}

	/**
	 * Method to initialise the credentials.  This will persist a temporary credentials set to be authorised by
	 * a resource owner.
	 *
	 * @param   string   $clientId      The key of the client requesting the temporary credentials.
	 * @param   string   $clientSecret  The secret key of the client requesting the temporary credentials.
	 * @param   string   $callbackUrl   The callback URL to set for the temporary credentials.
	 * @param   string   $lifetime      How long (DateInterval format) the temporary credentials should be valid (defaults to 60 minutes).
	 *
	 * @url http://php.net/manual/en/class.dateinterval.php
	 *
	 * @return  Oauth2CredentialsState
	 *
	 * @since   1.0
	 * @throws  LogicException
	 */
	public function initialise($clientId, $clientSecret, $callbackUrl, $lifetime = 'PT4H')
	{
		// Setup the properties for the credentials.
		$this->table->credentials_id = null;
		$this->table->callback_url = $callbackUrl;
		$this->table->client_id = $clientId;
		$this->table->client_secret = $clientSecret;
		$this->table->client_ip = $_SERVER['REMOTE_ADDR'];
		$this->table->temporary_token = $this->randomKey();
		$this->table->resource_uri = $callbackUrl;
		$this->table->type = Credentials::TEMPORARY;

		// Set the correct date adding the lifetime
		// @@ TODO: Fix static timezone
		$date = JFactory::getDate('now', 'America/Buenos_Aires');
		$date->add(new DateInterval($lifetime));
		$this->table->expiration_date = $date->toSql(true);

		// Persist the object in the database.
		$this->create();

		return new Temporary($this->table);
	}

	/**
	 * Method to revoke a set of token credentials.
	 *
	 * @return  Oauth2CredentialsState
	 *
	 * @since   1.0
	 * @throws  LogicException
	 */
	public function revoke()
	{
		throw new LogicException('Only token credentials can be revoked.');
	}
}
