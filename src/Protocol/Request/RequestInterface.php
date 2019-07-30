<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Protocol\Request;

/**
 * Header class
 *
 * @package  Joomla.Framework
 * @since    1.0
 */
interface RequestInterface
{
	/**
	 * Method to get the OAuth message string for signing.
	 *
	 * @return  array  The filtered params
	 *
	 * @since   1.0
	 */
	public function processVars();
}
