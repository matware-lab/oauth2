<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Controller;

use Joomla\OAuth2\Credentials\Credentials;
use Joomla\CMS\Factory;

/**
 * OAuth Controller class for initiating temporary credentials.
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       1.0
 */
class Resource extends Base
{
	/**
	 * Handle the Request.
	 *
	 * @return  void
	 *
	 * @since   1.0
	 */
	public function execute()
	{
		// Verify that we have an OAuth 2.0 application.
		$this->initialise();

		// Generate temporary credentials for the client.
		$credentials = new Credentials($this->request);
		$credentials->load();

		// Getting the client object
		$client = $this->fetchClient($this->request->client_id);

		// Ensure the credentials are authorised.
		if ($credentials->getType() !== Credentials::TOKEN)
		{
			$this->respondError(400, 'invalid_request', 'The token is not for a valid credentials yet.');
		}

		// Load the JUser class on application for this client
		$this->app->loadIdentity(Factory::getUser($client->id));
	}
}
