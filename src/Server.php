<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2;

use Joomla\Registry\Registry;
use Joomla\Http\Http;
use Joomla\CMS\Application;
use Joomla\Application\AbstractWebApplication;
use Joomla\OAuth2\Protocol\Request;
use Joomla\OAuth2\Controller\Initialise;
use Joomla\OAuth2\Controller\Authorise;
use Joomla\OAuth2\Controller\Convert;
use Joomla\OAuth2\Controller\Resource;

/**
 * Joomla! Oauth2 Server class
 *
 * @package  Joomla.Framework
 * @since    1.0
 */
class Server
{
	/**
	 * @var    Registry  Options for the Oauth2Client object.
	 * @since  1.0
	 */
	protected $options;

	/**
	 * @var    AbstractApplication  The Web Application receiving the request.
	 * @since  1.0
	 */
	protected $app;

	/**
	 * @var    Http  The HTTP client object to use in sending HTTP requests.
	 * @since  1.0
	 */
	protected $http;

	/**
	 * @var    Request  The input object to use in retrieving GET/POST data.
	 * @since  1.0
	 */
	protected $request;

	/**
	 * Constructor.
	 *
	 * @param   AbstractApplication    $app      The Joomla Application Object
	 * @param   Registry               $options  The options object.
	 * @param   Http                   $http     The HTTP client object.
	 * @param   Request                $request  The Request object.
	 *
	 * @since   1.0
	 * @throws
	 */
	public function __construct(AbstractWebApplication $app, Registry $options = null, Http $http = null, Request $request = null)
	{
		// Setup the options object.
		$this->options = isset($options) ? $options : new Registry;

		// Setup the Http object.
		$this->http = isset($http) ? $http : new Http($this->options);

		// Setup the Request object.
		$this->request = isset($request) ? $request : new Request($app);

		// Get application instance
		$this->app = $app;
	}

	/**
	 * Method to get the REST parameters for the current Request. Parameters are retrieved from these locations
	 * in the order of precedence as follows:
	 *
     * TODO: I think this is either GET or POST or Options after Auth Header not both Post and Get
	 *   - Authorization header
	 *   - POST variables
	 *   - GET query string variables
	 *
	 * @return  boolean  True if an REST message was found in the Request.
	 *
	 * @since   1.0
	 */
	public function listen()
	{
		// Get the OAuth 2.0 message from the Request if there is one.
		$found = $this->request->fetchMessageFromRequest();

		if (!$found)
		{
			return false;
		}

		// If we found an REST message somewhere we need to set the URI and Request method.
		if ($found && isset($this->request->response_type) && !isset($this->request->access_token))
		{
			// Load the correct controller type
			switch ($this->request->response_type)
			{
				case 'temporary':

					$controller = new Initialise($this->request);

					break;

				case 'authorise':

					$controller = new Authorise($this->request);

					break;
				case 'refresh_token':
				case 'token':

					$controller = new Convert($this->request);

					break;
				default:
					throw new \InvalidArgumentException('No valid response type was found.');
					break;
			}

			// Execute the controller
			$controller->execute();

			// Exit
			$this->app->close();
		}

		// If we found an REST message somewhere we need to set the URI and Request method.
		if ($found && isset($this->request->access_token))
		{
			$controller = new Resource($this->request);
			$controller->execute();
		}

		return $found;
	}
}
