<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Protocol\Request;

use Joomla\OAuth2\Protocol\Request;
use Joomla\Input\Input;

/**
 * RequestOptions class
 *
 * @package  Joomla.Framework
 * @since    1.0
 */
class RequestOptions implements RequestInterface
{
	/**
	 * @var    Input  The Joomla Input Object.
	 * @since  1.0
	 */
	private $input;

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
	 * Parse the Request OPTIONS variables for OAuth parameters.
	 *
	 * @return  mixed  Array of OAuth 2.0 parameters if found or boolean false otherwise.
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
			$value = $this->input->get->getString('oauth_' . $k, false);

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
}
