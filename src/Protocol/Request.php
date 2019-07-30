<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Protocol;

use Joomla\Application\AbstractWebApplication;
use Joomla\Input\Input;
use Joomla\OAuth2\Protocol\Request\RequestInterface;
use Joomla\Uri\Uri;
use Joomla\CMS\Factory;
use Joomla\OAuth2\Table\CredentialsTable;
use Joomla\OAuth2\Protocol\Request\RequestHeader;

/**
 * Request class
 *
 * @package  Joomla.Framework
 * @since    1.0
 */
class Request
{
	/**
	 * @var    Input  The Joomla Input Object.
	 * @since  1.0
	 */
	private $input;

	/**
	 * @var    string  The HTTP Request method for the message.
	 * @since  1.0
	 */
	public $method;

	/**
	 * @var    array  Associative array of parameters for the REST message.
	 * @since  1.0
	 */
	public $_headers = array();

	/**
	 * @var    string
	 * @since  1.0
	 */
	public $_identity;

	/**
	 * @var    string
	 * @since  1.0
	 */
	public $_credentials;

	/**
	 * @var    array  List of possible OAuth 2.0 parameters.
	 * @since  1.0
	 */
	static protected $_oauth_reserved = array(
		'client_id',
		'client_secret',
		'signature_method',
		'response_type',
		'scope',
		'state',
		'redirect_uri',
		'error',
		'error_description',
		'error_uri',
		'grant_type',
		'code',
		'access_token',
		'token_type',
		'expires_in',
		'username',
		'password',
		'refresh_token'
	);

	/**
	 * @var    Uri  The Request URI for the message.
	 * @since  1.0
	 */
	private $uri;

	/**
	 * Get the list of reserved OAuth 2.0 parameters.
	 *
	 * @return  array
	 *
	 * @since   1.0
	 */
	public static function getReservedParameters()
	{
		return self::$_oauth_reserved;
	}

	/**
	 * Method to get the OAUTH parameters.
	 *
	 * @return  array  $parameters  The OAUTH message parameters.
	 *
	 * @since   1.0
	 */
	public function getParameters()
	{
		$parameters = array();

		foreach (self::$_oauth_reserved as $k => $v)
		{
			if (isset($this->$v))
			{
				$parameters[$v] = $this->$v;
			}
		}

		return $parameters;
	}

	/**
	 * Method to set the REST message parameters.  This will only set valid REST message parameters.  If non-valid
	 * parameters are in the input array they will be ignored.
	 *
	 * @param   array $parameters The REST message parameters to set.
	 *
	 * @return  void
	 *
	 * @since   1.0
	 */
	public function setParameters($parameters)
	{
		// Ensure that only valid REST parameters are set if they exist.
		if (!empty($parameters))
		{
			foreach ($parameters as $k => $v)
			{
				if (0 === strpos($k, 'OAUTH_'))
				{
					$key        = strtolower(substr($k, 6));
					$this->$key = $v;
				}
			}
		}
	}

	/**
	 * Object constructor.
	 *
	 * @param   AbstractWebApplication  $app    The Joomla Application Object
	 * @param   CredentialsTable        $table  Connector object for table class.
	 *
	 * @since   1.0
	 * @throws
	 */
	public function __construct(AbstractWebApplication $app, CredentialsTable $table = null)
	{
		// Setup the database object.
		$this->input = $app->input;

		// Get URI
		$this->uri = new Uri($app->get('uri.request'));

		// Getting the Request method (POST||GET)
		$this->method = $this->input->getMethod();
	}

	public function getUri()
	{
		return $this->uri;
	}

	/**
	 * Check if the incoming Request is signed using OAuth 2.0.  To determine this, OAuth parameters are searched
	 * for in the order of precedence as follows:
	 *
	 *   * Authorization header.
	 *   * POST variables.
	 *   * GET query string variables.
	 *
	 * @return  boolean  True if parameters found, false otherwise.
	 *
	 * @since   1.0
	 */
	public function fetchMessageFromRequest()
	{
		// Init flag
		$flag = false;

		// Loading the response class
		$requestHeader = new RequestHeader;

		// First we look and see if we have an appropriate Authorization header.
		$authorization = $requestHeader->fetchAuthorizationHeader();

		if ($authorization)
		{
			$this->_headers = $requestHeader->processAuthorizationHeader($authorization);

			if ($this->_headers)
			{
				// Bind the found parameters to the OAuth 2.0 message.
				$this->setParameters($this->_headers);

				$flag = true;
			}
		}

		// Getting the method
		$method = strtolower($this->method);

		// Building the class name
		$class = '\Joomla\OAuth2\Protocol\Request\Request' . ucfirst($method);

		/** @var  RequestInterface $request */
		$request = new $class($this->input);

		// If we didn't find an Authorization header or didn't find anything in it try the POST variables.
		$params = $request->processVars();

		if ($params)
		{
			// Bind the found parameters to the OAuth 2.0 message.
			$this->setParameters($params);

			$flag = true;
		}

		// TODO: Check errors

		return $flag;
	}
}
