<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

defined('_JEXEC') or die( 'Restricted access' );

namespace Joomla\OAuth2;

use Joomla\OAuth2\Protocol\Request;
use Joomla\OAuth2\Protocol\Response;
use Joomla\OAuth2\Credentials\Credentials;
use Joomla\OAuth2\Controller\Base;


/**
 * OAuth Controller class for initiating temporary credentials.
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       1.0
 */
class Initialise extends Base
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

		// Get the client object
		$client = $this->fetchClient($this->request->client_id);

		// Doing authentication using Joomla! users
		if ($credentials->doJoomlaAuthentication($client) == false)
		{
			$this->respondError(400, 'unauthorized_client', 'The Joomla! credentials are not valid.');
		}

		// Load the JUser class on application for this client
		$this->app->loadIdentity($client->identity);

		// Initialize the credentials for this Request
		$credentials->initialise(
			$client->identity->id,
			$this->app->get('oauth.tokenlifetime', 'PT4H')
		);

		// Build the response for the client.
		$response = array(
			'oauth_code' => $credentials->getTemporaryToken(),
			'oauth_state' => true
		);

		// Check if the Request is CORS ( Cross-origin resource sharing ) and change the body if true
 		$body = $this->prepareBody($response);

		// Set the response code and body.
		$this->response->setHeader('status', '200')
			->setBody($body)
			->respond();
	}
}
