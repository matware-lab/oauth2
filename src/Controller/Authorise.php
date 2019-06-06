<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

defined('_JEXEC') or die( 'Restricted access' );

namespace Joomla\OAuth2\Controller;

use Joomla\OAuth2\Protocol\Request;
use Joomla\OAuth2\Protocol\Response;
use Joomla\OAuth2\Credentials\Credentials;

/**
 * OAuth Controller class for authorising temporary credentials.
 *
 * According to RFC 5849, this must be handled using a GET Request, so route accordingly. When implementing this in your own
 * app you should provide some means of protection against CSRF attacks.
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       12.3
 */
class Authorise extends Base
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
	 * @since   12.3
	 */
	public function execute()
	{
		// Verify that we have an rest api application.
		$this->initialise();

		// Generate temporary credentials for the client.
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

		// Verify that we have a signed in user.
		if (isset($this->request->code) && $credentials->getTemporaryToken() !== $this->request->code)
		{
			$this->respondError(400, 'invalid_grant', 'Temporary token is not valid');
		}

		// Ensure the credentials are temporary.
		if ( (int) $credentials->getType() !== Oauth2Credentials::TEMPORARY)
		{
			$this->respondError(400, 'invalid_request', 'The token is not for a temporary credentials set.');
		}

		// Verify that we have a signed in user.
		if ($this->app->getIdentity()->get('guest'))
		{
			$this->respondError(400, 'unauthorized_client', 'You must first sign in.');
		}

		// Attempt to authorise the credentials for the current user.
		$credentials->authorise($this->app->getIdentity()->get('id'));

		/*
		if ($credentials->getCallbackUrl() && $credentials->getCallbackUrl() != 'oob')
		{
			$this->app->redirect($credentials->getCallbackUrl());

			return;
		}
		*/
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
		exit;
	}
}
