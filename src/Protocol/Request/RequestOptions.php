<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Protocol\Request;

/**
 * Oauth2ProtocolRequestOptions class
 *
 * @package  Joomla.Framework
 * @since    1.0
 */
class RequestOptions
{
	/**
	 * Object constructor.
	 *
	 * @since   1.0
	 */
	public function __construct()
	{
		$this->app = JFactory::getApplication();

		// Setup the database object.
		$this->_input = $this->app->input;
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
		// Get a JURI instance for the Request URL.
		$uri = new JURI($this->app->get('uri.Request'));

		// Initialise params array.
		$params = array();

		// Iterate over the reserved parameters and look for them in the POST variables.
		foreach (Oauth2ProtocolRequest::getReservedParameters() as $k)
		{
			if ($this->_input->get->getString('oauth_' . $k, false))
			{
				$params['OAUTH_' . strtoupper($k)] = trim($this->_input->get->getString('oauth_' . $k));
			}
		}

		// Make sure that any found oauth_signature is not included.
		unset($params['signature']);

		// Ensure the parameters are in order by key.
		ksort($params);

		return $params;
	}
}
