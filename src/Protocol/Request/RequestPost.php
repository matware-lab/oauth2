<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Protocol\Request;

use Joomla\Input\Input;
use Joomla\OAuth2\Protocol\Request;

/**
 * RequestPost class
 *
 * @package  Joomla.Framework
 * @since    1.0
 */
class RequestPost implements RequestInterface
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
		$this->input = $input;
	}

	/**
	 * Parse the Request POST variables for OAuth parameters.
	 *
	 * @return  mixed  Array of OAuth 2.0 parameters if found or boolean false otherwise.
	 *
	 * @since   1.0
	 */
	public function processVars()
	{
		// If we aren't handling a post Request with urlencoded vars then there is nothing to do.
		if (strtoupper($this->input->getMethod()) !== 'POST'
			|| !strpos($this->input->server->get('CONTENT_TYPE', ''), 'x-www-form-urlencoded') )
		{
			return false;
		}

		// Initialise variables.
		$parameters = array();

		// Iterate over the reserved parameters and look for them in the POST variables.
		foreach (Request::getReservedParameters() as $k)
		{
			$value = $this->input->post->getString('oauth_' . $k, false);

			if ($value)
			{
				$parameters['OAUTH_' . strtoupper($k)] = trim($value);
			}
		}

		// If we didn't find anything return false.
		if (empty($parameters))
		{
			return false;
		}

		return $parameters;
	}
}
