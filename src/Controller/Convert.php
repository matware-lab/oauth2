<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Controller;

use Joomla\Controller\AbstractController;
use Joomla\OAuth2\Client;
use Joomla\OAuth2\Controller\Base;
use Joomla\OAuth2\Protocol\Request;
use Joomla\OAuth2\Protocol\Response;
use Joomla\OAuth2\Credentials\Credentials;

/**
 * OAuth Controller class for converting authorised credentials to token credentials.
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       12.3
 */
class Convert extends Base
{
	/**
	 * Constructor.
	 *
	 * @param   Oauth2ProtocolRequest   $request   The Request object
	 * @param   Oauth2ProtocolResponse  $response  The response object
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
	 * @since   12.3
	 */
	public function execute()
	{
		// Verify that we have an OAuth 2.0 application.
		$this->initialise();

		// Get the credentials for the Request.
		$credentials = new Credentials($this->request);
		$credentials->load();

		// Getting the client object
		$client = $this->fetchClient($this->request->client_id);

		// Doing authentication using Joomla! users
		if ($credentials->doJoomlaAuthentication($client) == false)
		{
			$this->respondError(400, 'unauthorized_client', 'The Joomla! credentials are not valid.');
		}

		// Load the JUser class on application for this client
		$this->app->loadIdentity($client->identity);

		// Ensure the credentials are authorised.
		if ($credentials->getType() !== Oauth2Credentials::TOKEN && $credentials->getType() !== Oauth2Credentials::AUTHORISED)
		{
			$this->respondError(400, 'invalid_request', 'The token is not for a temporary credentials set.');
		}

		// Convert the credentials to valid Token credentials for requesting protected resources.
		$credentials->convert();

		// Build the response for the client.
		$response = array(
			'access_token' => $credentials->getAccessToken(),
			'expires_in' => 'PT4H',
			'refresh_token' => $credentials->getRefreshToken()
		);

		// Check if the Request is CORS ( Cross-origin resource sharing ) and change the body if true
 		$body = $this->prepareBody($response);

		// Set the response code and body.
		$this->response->setHeader('status', '200')
			->setBody($body)
			->respond();
	}
}
