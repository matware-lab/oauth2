<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Controller;

use Joomla\OAuth2\Protocol\Request;
use Joomla\OAuth2\Protocol\Response;
use Joomla\OAuth2\Credentials\Credentials;
use Joomla\OAuth2\Controller\Base;
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
	 * Constructor.
	 *
	 * @param   Request   $request   The Request object
	 * @param   Response  $response  The response object
	 *
	 * @since   1.0
	 */
	public function __construct(Request $request = null, Response $response = null)
	{
		// Call parent first
		parent::__construct();

		// Setup the Request object.
		$this->request = isset($request) ? $request : new Request;

		// Setup the response object.
		$this->response = isset($response) ? $response : new Response;
	}

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
