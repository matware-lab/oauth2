<?php
/**
 * Part of the Joomla Framework OAuth2 Package
 *
 * @copyright  Copyright (C) 2005 - 2019 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth2\Table;

use Joomla\CMS\Table\Table;
use Joomla\CMS\Factory;
use Joomla\Database\DatabaseDriver;
use Joomla\CMS\Dispatcher\DispatcherInterface;

/**
 * OAuth2 Client Table
 *
 * @package     Joomla.Framework
 * @subpackage  OAuth2
 * @since       1.0
 */
class CredentialsTable extends Table
{
	/**
	 * Constructor
	 *
	 * @param   string              $table      The table name.
	 * @param   string              $key        The key of the table.
	 * @param   DatabaseDriver      $db         Database driver object.
	 * @param   DispatcherInterface $dispatcher Dispatcher object.
	 *
	 * @since   1.0
	 */
	public function __construct($table = '#__webservices_credentials', $key = 'credentials_id', DatabaseDriver $db = null, DispatcherInterface $dispatcher = null)
	{
		$db = !empty($db) ? $db : Factory::getDbo();

		parent::__construct($table, $key, $db, $dispatcher);
	}

	/**
	 * Delete expired credentials.
	 *
	 * @return  void
	 *
	 * @since   1.0
	 */
	public function clean()
	{
		// Build the query to delete the rows from the database.
		$query = $this->_db->getQuery(true);
		$query->delete('#__webservices_credentials')
			->where(array('DATE_ADD(expiration_date, INTERVAL 1 HOUR) < ' . $this->_db->quote(Factory::getDate('now')->toSql(true)),
				'expiration_date > 0'), 'AND');

		// Set and execute the query.
		$this->_db->setQuery($query);
		$this->_db->execute();

		$query = $this->_db->getQuery(true);
		$query->delete('#__webservices_credentials')
			->where(array('DATE_ADD(temporary_expiration_date, INTERVAL 1 HOUR) < ' . $this->_db->quote(Factory::getDate('now')->toSql(true))), 'AND');

		// Set and execute the query.
		$this->_db->setQuery($query);
		$this->_db->execute();
	}

	/**
	 * Load the credentials by key.
	 *
	 * @param   string $key The key for which to load the credentials.
	 * @param   string $uri The uri from the Request.
	 *
	 * @return  boolean
	 *
	 * @since 1.0
	 */
	public function loadBySecretKey($key, $uri)
	{
		// Build the query to load the row from the database.
		$query = $this->_db->getQuery(true);
		$query->select('*')
			->from('#__webservices_credentials')
			->where($this->_db->quoteName('client_secret') . ' = ' . $this->_db->quote($key));
		//->where($this->_db->quoteName('resource_uri') . ' = ' . $this->_db->quote($uri));
		$query->order('credentials_id DESC');
		$query->setLimit(1);

		// Set and execute the query.
		$this->_db->setQuery($query);
		$properties = $this->_db->loadAssoc();

		if (!is_array($properties))
			return false;

		// Bind the result to the object
		if ($this->bind($properties))
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	/**
	 * Load the credentials by key.
	 *
	 * @param   string $key The key for which to load the credentials.
	 * @param   string $uri The uri from the Request.
	 *
	 * @return  boolean
	 *
	 * @since 1.0
	 */
	public function loadByAccessToken($key, $uri)
	{
		// Build the query to load the row from the database.
		$query = $this->_db->getQuery(true);
		$query->select('*')
			->from('#__webservices_credentials')
			->where($this->_db->quoteName('access_token') . ' = ' . $this->_db->quote($key))
			->where($this->_db->quoteName('expiration_date') . ' > ' . $this->_db->quote(Factory::getDate('now')->toSql(true)));
		//->where($this->_db->quoteName('resource_uri') . ' = ' . $this->_db->quote($uri));

		// Set and execute the query.
		$this->_db->setQuery($query);
		$properties = $this->_db->loadAssoc();

		if (!is_array($properties))
			return false;

		// Bind the result to the object
		if ($this->bind($properties))
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	/**
	 * Load the credentials by key.
	 *
	 * @param   string $key The key for which to load the credentials.
	 * @param   string $uri The uri from the Request.
	 *
	 * @return  void
	 *
	 * @since 1.0
	 */
	public function loadByRefreshToken($key, $uri)
	{
		// Build the query to load the row from the database.
		$query = $this->_db->getQuery(true);
		$query->select('*')
			->from('#__webservices_credentials')
			->where($this->_db->quoteName('refresh_token') . ' = ' . $this->_db->quote($key))
			->where($this->_db->quoteName('expiration_date') . ' > ' . $this->_db->quote(Factory::getDate('now')->toSql(true)));
		//->where($this->_db->quoteName('resource_uri') . ' = ' . $this->_db->quote($uri));

		// Set and execute the query.
		$this->_db->setQuery($query);
		$properties = $this->_db->loadAssoc();

		if (!is_array($properties))
			return false;

		// Bind the result to the object
		if ($this->bind($properties))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}
