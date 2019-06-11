<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */



namespace Joomla\OAuth2\Credentials\State;

use Joomla\Date\Date;
use LogicException;
use Joomla\OAuth2\Credentials\Credentials;

/**
 * OAuth2 Authorised Credentials class
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       1.0
 */
class Authorised extends State
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
	 * @param   string  $lifetime  How long (DateInterval format) the credentials should be valid (defaults to 60 minutes).
	 *
	 * @url http://php.net/manual/en/class.dateinterval.php
	 *
	 * @return  Token
	 *
	 * @since   1.0
	 * @throws  LogicException
	 */
	public function convert($lifetime = 'PT4H')
	{
		// Setup the properties for the credentials.
		$this->table->callback_url = '';
		$this->table->access_token = $this->randomKey();
		$this->table->refresh_token = $this->randomKey();
		$this->table->type = Credentials::TOKEN;

		// Set the correct date adding the lifetime
		// @@ TODO: Fix static timezone
		$date = new Date('now');
		$date->add(new DateInterval($lifetime));
		$this->table->expiration_date = $date->toSql(true);

		// Clean the temporary expitation date
		$this->table->temporary_expiration_date = 0;

		// Persist the object in the database.
		$this->update();

		return new Token($this->table);
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
	 * @param   integer  $lifetime      How long the credentials are good for.
	 *
	 * @return  void
	 *
	 * @since   1.0
	 * @throws  LogicException
	 */
	public function initialise($clientId, $clientSecret, $callbackUrl, $lifetime = 0)
	{
		throw new LogicException('Only new credentials can be initialised.');
	}

	/**
	 * Method to revoke a set of token credentials.
	 *
	 * @return  void
	 *
	 * @since   1.0
	 * @throws  LogicException
	 */
	public function revoke()
	{
		throw new LogicException('Only token credentials can be revoked.');
	}
}
