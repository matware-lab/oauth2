<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Controller;

use Joomla\Application\AbstractWebApplication;
use Joomla\Controller\AbstractController;
use Joomla\OAuth2\Protocol\Request;
use Joomla\OAuth2\Protocol\Response;
use Joomla\OAuth2\Table\ClientsTable;


/**
 * OAuth Controller class for initiating temporary credentials.
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       1.0
 */
abstract class Base extends AbstractController
{
    /**
     * The request object
     *
     * @var  Request
     */
    protected $request;

	/**
	 * Constructor.
	 *
	 * @param   Request                 $request   The Request object
     * @param   AbstractWebApplication  $app       The application object
	 *
	 * @since   1.0
	 * @throws
	 */
	public function __construct(Request $request, AbstractWebApplication $app)
	{
        $this->request = $request;

		parent::__construct($app->input, $app);
	}

	/**
	 * Initialise the controller
	 *
	 * @return  void
	 *
	 * @since   1.0
	 */
	protected function initialise()
	{
		// Verify that we have an OAuth 2.0 application.
		//if ((!$this->app instanceof Joomla\CMS\Application\ApiApplication))
		//{
		//	$this->respondError(400, 'invalid_request', 'Cannot perform OAuth 2.0 authorisation without an OAuth 2.0 application.');
		//}

		// We need a valid signature to do initialisation.
		if (!isset($this->request->access_token) && (!$this->request->client_id || !$this->request->client_secret || !$this->request->signature_method) )
		{
			$this->respondError(400, 'invalid_request', 'Invalid OAuth Request signature.');
		}
	}

	/**
	 * Get an OAuth 2.0 client object based on the Request message.
	 *
	 * @param   string  $client_id  The OAuth 2.0 client_id parameter for which to load the client.
	 *
	 * @return  ClientsTable
	 *
	 * @since   1.0
	 */
	public function fetchClient($client_id)
	{
		$client_id = base64_decode($client_id);
		$client_id = explode(":", $client_id);
		$client_id = $client_id[0];

		// Ensure there is a consumer key.
		if (empty($client_id))
		{
			$this->respondError(400, 'unauthorized_client', 'There is no OAuth consumer key in the Request.');
		}

		// Get an OAuth client object and load it using the incoming client key.
		$client = new ClientsTable();
		$client->loadByKey($client_id);

		// Verify the client key for the message.
		if ($client->username != $client_id)
		{
			$this->respondError(400, 'unauthorized_client', 'The OAuth consumer key is not valid.');
		}

		return $client;
	}

	/**
	 * Return the JSON message for CORS or simple Request.
	 *
	 * @param   array	$message	The return message
	 *
	 * @return  string	$body	    The message prepared if CORS is enabled, or same if false.
	 *
	 * @since   1.0
	 */
	public function prepareBody($message)
	{
		$callback = $this->app->input->get->getString('callback', false);

		if ($callback !== false)
		{
			$body = $callback . '(' . json_encode($message) . ')';
		}
		else
		{
			$body = json_encode($message);
		}

		return $body;
	}

	/**
	 * Return the JSON error based on RFC 6749 (http://tools.ietf.org/html/rfc6749#section-5.2)
	 *
	 * @param   int     $status   The HTTP protocol status. Default: 400 for errors
	 * @param   string  $code     The OAuth2 framework error code
	 * @param   string  $message  The error description
	 *
	 * @return  void
	 *
	 * @since   1.0
	 */
	public function respondError($status, $code, $message)
	{
		$response = array(
			'error' => $code,
			'error_description' => $message
		);

		$this->app->setHeader('status', $status)
			->setBody(json_encode($response))
			->respond();

		$this->app->close();
	}
}
