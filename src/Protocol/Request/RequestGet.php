<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Protocol\Request;

use Joomla\OAuth2\Protocol\Request;
use Joomla\Uri\Uri;
use Joomla\Input\Input;

/**
 * RequestGet class
 *
 * @package  Joomla.Framework
 * @since    1.0
 */
class RequestGet implements RequestInterface
{
	/**
	 * @var    Input  The Joomla Input Object.
	 * @since  1.0
	 */
	private $_input;

	/**
	 * Object constructor.
	 *
	 * @param   Input  $input  The Joomla Input Object
	 *
	 * @since   1.0
	 */
	public function __construct(Input $input)
	{
		// Setup the database object.
		$this->_input = $input;
	}

	/**
	 * Method to get the OAuth message string for signing.
	 *
	 * @return  array  The filtered params
	 *
	 * @since   1.0
	 */
	public function processVars()
	{
		// Initialise params array.
		$params = array();

		// Iterate over the reserved parameters and look for them in the POST variables.
		foreach (Request::getReservedParameters() as $k)
		{
			$value = $this->_input->get->getString('oauth_' . $k, false);

			if ($value)
			{
				$params['OAUTH_' . strtoupper($k)] = trim($value);
			}
		}

		// Make sure that any found oauth_signature is not included.
		// TODO: I think this should this be oauth_signature instead of signature (and probably uppercase?)
		unset($params['signature']);

		// Ensure the parameters are in order by key.
		ksort($params);

		return $params;
	}

	/**
	 * Method to get the OAuth message string for signing.
	 *
	 * Note: As of PHP 5.3 the $this->encode() function is RFC 3986 compliant therefore this requires PHP 5.3+
	 *
	 * @param   string  $requestUrl     The message's Request URL.
	 * @param   string  $requestMethod  The message's Request method.
	 *
	 * @return  string  The unsigned OAuth message string.
	 *
	 * @link    http://www.faqs.org/rfcs/rfc3986
	 * @see     $this->encode()
	 * @since   1.0
	 *
	 * TODO: This function appears to be unused. I assume this used to live in the Request class given the methods it
	 *       calls. Check if it's required?
	 */
	public function _fetchStringForSigning($requestUrl, $requestMethod)
	{
		// Get a Uri instance for the Request URL.
		$uri = new Uri($requestUrl);

		// Initialise base array.
		$base = array();

		// Get the found parameters.
		$params = $this->getParameters();

		// Add the variables from the URI query string.
		foreach ($uri->getQuery(true) as $k => $v)
		{
			if (strpos($k, 'oauth_') !== 0)
			{
				$params[$k] = $v;
			}
		}

		// Make sure that any found oauth_signature is not included.
		unset($params['oauth_signature']);

		// Ensure the parameters are in order by key.
		ksort($params);

		// Iterate over the keys to add properties to the base.
		foreach ($params as $key => $value)
		{
			// If we have multiples for the parameter let's loop over them.
			if (is_array($value))
			{
				// Don't want to do this more than once in the inner loop.
				$key = $this->encode($key);

				// Sort the value array and add each one.
				sort($value, SORT_STRING);

				foreach ($value as $v)
				{
					$base[] = $key . '=' . $this->encode($v);
				}
			}

			// The common case is that there is one entry per property.
			else
			{
				$base[] = $this->encode($key) . '=' . $this->encode($value);
			}
		}

		// Start off building the base string by adding the Request method and URI.
		$base = array(
			$this->encode(strtoupper($requestMethod)),
			$this->encode(strtolower($uri->toString(array('scheme', 'user', 'pass', 'host', 'port'))) . $uri->getPath()),
			$this->encode(implode('&', $base))
		);

		return implode('&', $base);
	}
}
