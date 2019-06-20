<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2;

use InvalidArgumentException;
use Joomla\Application\AbstractWebApplication;
use Joomla\Http\Exception\UnexpectedResponseException;
use Joomla\Http\Http;
use Joomla\Input\Input;
use RuntimeException;

/**
 * Joomla Framework class for interacting with an OAuth 2.0 server.
 *
 * @since  1.0
 */
class OAuth2Client
{
	/**
	 * @var    array  Options for the Client object.
	 * @since  1.0
	 */
	protected $options;

	/**
	 * @var    Http  The HTTP client object to use in sending HTTP requests.
	 * @since  1.0
	 */
	protected $http;

	/**
	 * @var    Input  The input object to use in retrieving GET/POST data.
	 * @since  1.0
	 */
	protected $input;

	/**
	 * @var    AbstractWebApplication  The application object to send HTTP headers for redirects.
	 * @since  1.0
	 */
	protected $application;

	/**
	 * Constructor.
	 *
	 * @param   array                   $options      OAuth2 Client options object
	 * @param   Http                    $http         The HTTP client object
	 * @param   Input                   $input        The input object
	 * @param   AbstractWebApplication  $application  The application object
	 *
	 * @since   1.0
	 */
	public function __construct($options = array(), Http $http, Input $input, AbstractWebApplication $application = null)
	{
		$this->options     = $options;
		$this->http        = $http;
		$this->input       = $input;
		$this->application = $application;
	}

	/**
	 * Fetch the access token making the OAuth 2.0 method process
	 *
	 * @return    object    Returns the token object
	 *
	 * @throws    Exception
	 * @since    1.0
	 */
	public function fetchAccessToken()
	{
		// Execute the temporary token
		try
		{
			// Create the request array to be sent
			$append = array(
				'oauth_response_type' => 'temporary'
			);
			$code   = (object) $this->getPostRequest($append);
		}
		catch (RuntimeException $e)
		{
			throw new RuntimeException($e->getMessage());
		}


		// Get authorization token
		try
		{
			// Create the request array to be sent
			$append = array(
				'oauth_grant_type'    => 'authorization_code',
				'oauth_response_type' => 'authorise',
				'oauth_code'          => $code->oauth_code
			);
			$code   = (object) $this->getPostRequest($append);
		}
		catch (RuntimeException $e)
		{
			throw new RuntimeException($e->getMessage());
		}

		// Get access token
		try
		{
			// Create the request array to be sent
			$append = array(
				'oauth_response_type' => 'token',
				'oauth_code'          => $code->oauth_code
			);
			$token  = (object) $this->getPostRequest($append);
		}
		catch (RuntimeException $e)
		{
			throw new RuntimeException($e->getMessage());
		}

		return $token;
	}

	/**
	 * Get the request for post
	 *
	 * @param   array  $append  The array with oauth parameters to append
	 *
	 * @return	string	Returns authentication token
	 *
	 * @since 	1.0
	 * @throws	Exception
	 */
	public function getPostRequest($append = array())
	{
		// Get the headers
		$data = $this->getPostData();

		// Append parameters to existing data
		$data = $data + $append;

		// Send the request
		$response = $this->http->post($this->options->get('url'), $data, $this->getRestHeaders(true));

		// Process the response
		$token = $this->processRequest($response);

		return $token;
	}

	/**
	 * Get the access token or redirect to the authentication URL.
	 *
	 * @return  string  The access token
	 *
	 * @throws  RuntimeException
	 * @since   1.0
	 */
	public function authenticate()
	{
		if ($data['code'] = $this->input->get('code', false, 'raw'))
		{
			$data = array(
				'grant_type'    => 'authorization_code',
				'redirect_uri'  => $this->getOption('redirecturi'),
				'client_id'     => $this->getOption('clientid'),
				'client_secret' => $this->getOption('clientsecret'),
			);

			$response = $this->http->post($this->getOption('tokenurl'), $data);

			if ($response->code >= 200 && $response->code < 400)
			{
				if (strpos($response->headers['Content-Type'], 'application/json') !== false)
				{
					$token = array_merge(json_decode($response->body, true), array('created' => time()));
				}
				else
				{
					parse_str($response->body, $token);
					$token = array_merge($token, array('created' => time()));
				}

				$this->setToken($token);

				return $token;
			}

			// As of 2.0 this will throw an UnexpectedResponseException
			throw new RuntimeException('Error code ' . $response->code . ' received requesting access token: ' . $response->body . '.');
		}

		if ($this->getOption('sendheaders'))
		{
			if ($this->application instanceof AbstractWebApplication)
			{
				$this->application->redirect($this->createUrl());
			}
			else
			{
				throw new RuntimeException('AbstractWebApplication object required for authentication process.');
			}
		}

		return false;
	}

	/**
	 * Verify if the client has been authenticated
	 *
	 * @return  boolean  Is authenticated
	 *
	 * @since   1.0
	 */
	public function isAuthenticated()
	{
		$token = $this->getToken();

		if (!$token || !array_key_exists('access_token', $token))
		{
			return false;
		}

		if (array_key_exists('expires_in', $token) && $token['created'] + $token['expires_in'] < time() + 20)
		{
			return false;
		}

		return true;
	}

	/**
	 * Create the URL for authentication.
	 *
	 * @return  string
	 *
	 * @throws  InvalidArgumentException
	 * @since   1.0
	 */
	public function createUrl()
	{
		if (!$this->getOption('authurl') || !$this->getOption('clientid'))
		{
			throw new InvalidArgumentException('Authorization URL and client_id are required');
		}

		$url = $this->getOption('authurl');

		if (strpos($url, '?'))
		{
			$url .= '&';
		}
		else
		{
			$url .= '?';
		}

		$url .= 'response_type=code';
		$url .= '&client_id=' . urlencode($this->getOption('clientid'));

		if ($this->getOption('redirecturi'))
		{
			$url .= '&redirect_uri=' . urlencode($this->getOption('redirecturi'));
		}

		if ($this->getOption('scope'))
		{
			$scope = \is_array($this->getOption('scope')) ? implode(' ', $this->getOption('scope')) : $this->getOption('scope');
			$url   .= '&scope=' . urlencode($scope);
		}

		if ($this->getOption('state'))
		{
			$url .= '&state=' . urlencode($this->getOption('state'));
		}

		if (\is_array($this->getOption('requestparams')))
		{
			foreach ($this->getOption('requestparams') as $key => $value)
			{
				$url .= '&' . $key . '=' . urlencode($value);
			}
		}

		return $url;
	}

	/**
	 * Send a signed Oauth Request.
	 *
	 * @param   string  $url      The URL for the Request.
	 * @param   mixed   $data     The data to include in the Request
	 * @param   array   $headers  The headers to send with the Request
	 * @param   string  $method   The method with which to send the Request
	 * @param   int     $timeout  The timeout for the Request
	 *
	 * @return  \Joomla\Http\Response  The http response object.
	 *
	 * @throws  InvalidArgumentException
	 * @throws  RuntimeException
	 * @since   1.0
	 */
	public function query($url, $data = null, $headers = array(), $method = 'get', $timeout = null)
	{
		$token = $this->getToken();

		if (array_key_exists('expires_in', $token) && $token['created'] + $token['expires_in'] < time() + 20)
		{
			if (!$this->getOption('userefresh'))
			{
				return false;
			}

			$token = $this->refreshToken($token['refresh_token']);
		}

		if (!$this->getOption('authmethod') || $this->getOption('authmethod') == 'bearer')
		{
			$headers['Authorization'] = 'Bearer ' . $token['access_token'];
		}
		elseif ($this->getOption('authmethod') == 'get')
		{
			if (strpos($url, '?'))
			{
				$url .= '&';
			}
			else
			{
				$url .= '?';
			}

			$url .= $this->getOption('getparam') ? $this->getOption('getparam') : 'access_token';
			$url .= '=' . $token['access_token'];
		}

		switch ($method)
		{
			case 'head':
			case 'get':
			case 'delete':
			case 'trace':
				$response = $this->http->$method($url, $headers, $timeout);

				break;

			case 'post':
			case 'put':
			case 'patch':
				$response = $this->http->$method($url, $data, $headers, $timeout);

				break;

			default:
				throw new InvalidArgumentException('Unknown HTTP Request method: ' . $method . '.');
		}

		if ($response->code < 200 || $response->code >= 400)
		{
			// As of 2.0 this will throw an UnexpectedResponseException
			throw new RuntimeException('Error code ' . $response->code . ' received requesting data: ' . $response->body . '.');
		}

		return $response;
	}

	/**
	 * Get an option from the OAuth2 Client instance.
	 *
	 * @param   string  $key  The name of the option to get
	 *
	 * @return  mixed  The option value
	 *
	 * @since   1.0
	 */
	public function getOption($key)
	{
		return isset($this->options[$key]) ? $this->options[$key] : null;
	}

	/**
	 * Set an option for the OAuth2 Client instance.
	 *
	 * @param   string  $key    The name of the option to set
	 * @param   mixed   $value  The option value to set
	 *
	 * @return  Client  This object for method chaining
	 *
	 * @since   1.0
	 */
	public function setOption($key, $value)
	{
		$this->options[$key] = $value;

		return $this;
	}

	/**
	 * Get the access token from the Client instance.
	 *
	 * @return  array  The access token
	 *
	 * @since   1.0
	 */
	public function getToken()
	{
		return $this->getOption('accesstoken');
	}

	/**
	 * Set an option for the Client instance.
	 *
	 * @param   array  $value  The access token
	 *
	 * @return  Client  This object for method chaining
	 *
	 * @since   1.0
	 */
	public function setToken($value)
	{
		if (\is_array($value) && !array_key_exists('expires_in', $value) && array_key_exists('expires', $value))
		{
			$value['expires_in'] = $value['expires'];
			unset($value['expires']);
		}

		$this->setOption('accesstoken', $value);

		return $this;
	}

	/**
	 * Refresh the access token instance.
	 *
	 * @param   string  $token  The refresh token
	 *
	 * @return  array  The new access token
	 *
	 * @throws  UnexpectedResponseException
	 * @throws  RuntimeException
	 * @since   1.0
	 */
	public function refreshToken($token = null)
	{
		if (!$this->getOption('userefresh'))
		{
			throw new RuntimeException('Refresh token is not supported for this OAuth instance.');
		}

		if (!$token)
		{
			$token = $this->getToken();

			if (!array_key_exists('refresh_token', $token))
			{
				throw new RuntimeException('No refresh token is available.');
			}

			$token = $token['refresh_token'];
		}

		$data = array(
			'grant_type'    => 'refresh_token',
			'refresh_token' => $token,
			'client_id'     => $this->getOption('clientid'),
			'client_secret' => $this->getOption('clientsecret'),
		);

		$response = $this->http->post($this->getOption('tokenurl'), $data);

		if ($response->code >= 200 || $response->code < 400)
		{
			if (strpos($response->headers['Content-Type'], 'application/json') !== false)
			{
				$token = array_merge(json_decode($response->body, true), array('created' => time()));
			}
			else
			{
				parse_str($response->body, $token);
				$token = array_merge($token, array('created' => time()));
			}

			$this->setToken($token);

			return $token;
		}

		throw new UnexpectedResponseException(
			$response,
			sprintf(
				'Error code %s received refreshing token: %s.',
				$response->code,
				$response->body
			)
		);
	}

	/**
	 * Get the rest headers to send
	 *
	 * @param   string  $form  True if we like to use POST
	 *
	 * @return  array   The RESTful headers
	 *
	 * @since   1.0
	 */
	protected function getRestHeaders($form = false)
	{
		// Encode the headers for REST
		$user_encode   = $this->encode($this->options->get('username'), $this->rest_key);
		$pw_encode     = $this->encode($this->options->get('password'), $this->rest_key);
		$authorization = $this->encode($user_encode, $pw_encode, true);
		$headers       = array(
			'Authorization' => 'Bearer ' . base64_encode($authorization)
		);
		if ($form === true)
		{
			$headers['Content-Type'] = 'application/x-www-form-urlencoded';
		}

		return $headers;
	}

	/**
	 * Get the POST data to send
	 *
	 * @return  array   The POST data to send
	 *
	 * @since   1.0
	 */
	protected function getPostData()
	{
		// Set the user and password to headers
		$rest_key = $this->randomKey();

		// Encode the headers for REST
		$user_encode   = $this->encode($this->options->get('username'), $this->rest_key);
		$pw_encode     = $this->encode($this->options->get('password'), $this->rest_key);
		$client_secret = $this->encode($this->randomKey(), $pw_encode, true);

		$post          = array(
			'oauth_client_id'        => base64_encode($user_encode),
			'oauth_client_secret'    => base64_encode($client_secret),
			'oauth_signature_method' => $this->options->get('signature_method')
		);

		return $post;
	}

	/**
	 * Encode the string with the key
	 *
	 * @param   string   $string  The string to encode.
	 * @param   string   $key     The key to encode the string.
	 * @param   boolean  $base64  True to encode the strings.
	 *
	 * @return  string
	 *
	 * @since   1.0
	 */
	protected function encode($string, $key, $base64 = false)
	{
		if ($base64 === true)
		{
			$return = base64_encode($string) . ":" . base64_encode($key);
		}
		else
		{
			$return = "{$string}:{$key}";
		}

		return $return;
	}

	/**
	 * Generate a random (and optionally unique) key.
	 *
	 * @param   boolean  $unique  True to enforce uniqueness for the key.
	 *
	 * @return  string
	 *
	 * @since   1.0
	 */
	protected function randomKey($unique = false)
	{
		$str = md5(uniqid(rand(), true));
		if ($unique)
		{
			list ($u, $s) = explode(' ', microtime());
			$str .= dechex($u) . dechex($s);
		}

		return $str;
	}
}
