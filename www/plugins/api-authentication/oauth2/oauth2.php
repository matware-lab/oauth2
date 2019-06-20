<?php
/**
 * @version       $Id:
 * @package       Matware.Plugin
 * @subpackage    OAuth2
 * @copyright     Copyright (C) 2004 - 2019 Matware Consulting - All rights reserved.
 * @author        Matias Aguirre
 * @email         maguirre@matware.com.ar
 * @link          http://www.matware.com.ar/
 * @license       GNU/GPL http://www.gnu.org/licenses/gpl-2.0-standalone.html
 */

defined('_JEXEC') or die;

use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserHelper;
use Joomla\CMS\Language\Text;
use Joomla\OAuth2\Server;

/**
 * OAuth2 Authentication Plugin
 *
 * @package     Joomla.Plugin
 * @subpackage  Authentication.oauth2
 * @since       1.0.0
 */
class PlgApiAuthenticationOAuth2 extends CMSPlugin
{
	/**
	 * The application object
	 *
	 * @type   Application
	 * @since  1.0.0
	 */
	protected $app;

	/**
	 * The application object
	 *
	 * @type   \Joomla\Database\DatabaseInterface
	 * @since  1.0.0
	 */
	protected $db;

	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @return  boolean
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public function onBeforeExecute()
	{
		//if (!$this->isSSLConnection()) {
		//	exit;
		//}

		// Init the flag
		$request = false;

		// Load the Joomla! application
		$app = Factory::getApplication();

		// Get the OAuth2 server instance
		$oauth_server = new Server;

		if ($oauth_server->listen())
		{
			$request = true;
		}
	}

	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @param   array    $credentials  Array holding the user credentials
	 * @param   array    $options      Array of extra options
	 * @param   object  &$response     Authentication response object
	 *
	 * @return  void
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public function onUserAuthenticate($credentials, $options, &$response)
	{
		$this->onBeforeExecute();

		$response->type = 'OAuth2';

		$username = $this->app->input->server->get('PHP_AUTH_USER');
		$password = $this->app->input->server->get('PHP_AUTH_PW');

		if (empty($password))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');

			return;
		}

		$db    = $this->db;
		$query = $db->getQuery(true)
			->select($db->quoteName(['id', 'password']))
			->from($db->quoteName('#__users'))
			->where($db->quoteName('username') . ' = :username')
			->bind(':username', $username);

		$db->setQuery($query);
		$result = $db->loadObject();

		if ($result)
		{
			$match = UserHelper::verifyPassword($password, $result->password, $result->id);

			if ($match === true)
			{
				// Bring this in line with the rest of the system
				$user               = User::getInstance($result->id);
				$response->email    = $user->email;
				$response->fullname = $user->name;
				$response->username = $username;

				if ($this->app->isClient('administrator'))
				{
					$response->language = $user->getParam('admin_language');
				}

				else
				{
					$response->language = $user->getParam('language');
				}

				$response->status        = Authentication::STATUS_SUCCESS;
				$response->error_message = '';
			}
			else
			{
				// Invalid password
				$response->status        = Authentication::STATUS_FAILURE;
				$response->error_message = Text::_('JGLOBAL_AUTH_INVALID_PASS');
			}
		}
		else
		{
			// Let's hash the entered password even if we don't have a matching user for some extra response time
			// By doing so, we mitigate side channel user enumeration attacks
			UserHelper::hashPassword($password);

			// Invalid user
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('JGLOBAL_AUTH_NO_USER');
		}
	}

	/**
	 * Get the oauth2 token to save it in JSession
	 *
	 * @return  boolean  True if everything is ok, false if not.
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public function getToken($user, $password)
	{
		$url = JURI::base() . 'api/joomla:articles';

		$options                     = array();
		$options['username']         = $user->username;
		$options['password']         = $password;
		$options['method']           = "GET";
		$options['signature_method'] = 'PLAINTEXT';

		$registry = new JRegistry($options);

		// Initialise the OAuth 2.0 client
		$client = new MClientOAuth2($registry);

		// Send the initial session request
		$client->setOption('url', $url);

		return $client->fetchAccessToken()->access_token;
	}

	/**
	 * Determine if we are using a secure (SSL) connection.
	 *
	 * @return  boolean  True if using SSL, false if not.
	 *
	 * @since   1.0.0
	 */
	public function isSSLConnection()
	{
		return ((isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] == 'on')) || getenv('SSL_PROTOCOL_VERSION'));
	}
}
