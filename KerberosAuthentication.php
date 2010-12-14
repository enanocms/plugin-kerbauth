<?php
/**!info**
{
  "Plugin Name"  : "Kerberos authentication",
  "Plugin URI"   : "http://enanocms.org/plugin/kerbauth",
  "Description"  : "Allows authentication to Enano via Kerberos.",
  "Author"       : "Dan Fuhry",
  "Version"      : "1.0",
  "Author URI"   : "http://enanocms.org/",
  "Auth plugin"  : true
}
**!*/

/*
 * Kerberos authentication plugin for Enano
 * (C) 2010 Dan Fuhry
 *
 * This program is Free Software; you can redistribute and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for details.
 */

if ( getConfig('kerb_enable', 0) == 1 )
{
  $plugins->attachHook('login_process_userdata_json', 'return kerb_auth_hook($userinfo, $req["level"], @$req["remember"]);');
}

function kerb_auth_hook($userinfo, $level, $remember)
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  // First try to just authenticate the user in Kerberos
  require_once(ENANO_ROOT . '/plugins/kerbauth/libkrb5.php');
  
  if ( strstr($userinfo['username'], '/') )
  {
  	  return array(
  	  	  	'mode' => 'error',
  	  	  	'error' => 'You cannot log in with Kerberos principals containing slashes. This is due to both security reasons and Enano technical limitations.'
  	  	  );
  }
  
  // We're ready to do a Kerberos auth attempt
  try
  {
    $auth_result = krb5_verify_creds($userinfo['username'], $userinfo['password']);
  }
  catch ( KerberosError $e )
  {
    return array(
        'mode' => 'error',
        'error' => "The Kerberos interface returned a technical error."
      );
  }
  
  if ( $auth_result )
  {
    // Kerberos authentication was successful.
    $username = $db->escape(strtolower($userinfo['username']));
    $q = $db->sql_query("SELECT user_id, password FROM " . table_prefix . "users WHERE " . ENANO_SQLFUNC_LOWERCASE . "(username) = '$username';");
    if ( !$q )
      $db->_die();
    if ( $db->numrows() < 1 )
    {
      // This user doesn't exist.
      // Is creating it our job?
      if ( getConfig('kerb_disable_local_auth', 0) == 1 )
      {
        // Yep, register him
        $email = strtolower($userinfo['username']) . '@' . getConfig('kerb_email_domain', 'localhost');
        $random_pass = md5(microtime() . mt_rand());
        // load the language
        $session->register_guest_session();
        $reg_result = $session->create_user($userinfo['username'], $random_pass, $email);
        if ( $reg_result != 'success' )
        {
          // o_O
          // Registration failed.
          return array(
              'mode' => 'error',
              'error' => 'Your username and password were valid, but there was a problem instanciating your local user account.'
            );
        }
        // Get user ID
        $q = $db->sql_query("SELECT user_id, password FROM " . table_prefix . "users WHERE " . ENANO_SQLFUNC_LOWERCASE . "(username) = '$username';");
        if ( !$q )
          $db->_die();
        if ( $db->numrows() < 1 )
          return array(
              'mode' => 'error',
              'error' => 'Your username and password were valid, but there was a problem getting your user ID.'
            );
        $row = $db->fetchrow();
        $db->free_result();
        // Quick - lock the account
        $q = $db->sql_query('UPDATE ' . table_prefix . "users SET password = 'Locked by Kerberos plugin', password_salt = 'Locked by Kerberos plugin' WHERE user_id = {$row['user_id']};");
        if ( !$q )
          $db->_die();
        
        $row['password'] = 'Locked by Kerberos plugin';
      }
      else
      {
        // Nope. Just let Enano fail it properly.
        return null;
      }
    }
    else
    {
      $row = $db->fetchrow();
      $db->free_result();
    }
    
    $session->register_session(intval($row['user_id']), $userinfo['username'], $row['password'], intval($level), intval($remember));
    return true;
  }
  else
  {
    // Kerberos authentication failed.
    
    // Are local logons allowed?
    if ( getConfig('kerb_disable_local_auth', 0) == 0 )
    {
      // Yes, allow auth to continue
      return null;
    }
    
    // Block the login attempt unless the username is a local admin.
    $username = $db->escape(strtolower($userinfo['username']));
    $q = $db->sql_query("SELECT user_level FROM " . table_prefix . "users WHERE " . ENANO_SQLFUNC_LOWERCASE . "(username) = '$username';");
    if ( !$q )
      $db->_die();
    if ( $db->numrows() > 0 )
    {
      // Well, the user exists...
      list($ul) = $db->fetchrow_num();
      $db->free_result();
      if ( $ul >= USER_LEVEL_ADMIN )
      {
        // They're an admin, allow local logon
        return null;
      }
    }
    $db->free_result();
    
    // User doesn't exist, or is not an admin, and users are not allowed to log on locally. Lock them out.
    $q = $db->sql_query('INSERT INTO ' . table_prefix . "lockout(ipaddr, timestamp, action, username)\n"
                      . "  VALUES('" . $db->escape($_SERVER['REMOTE_ADDR']) . "', " . time() . ", 'credential', '" . $db->escape($userinfo['username']) . "');");
    if ( !$q )
      $db->_die();
    
    return array(
        'mode' => 'error',
        'error' => 'Invalid Kerberos authentication credentials.'
      );
  }
}

// Registration blocking hook
if ( getConfig('kerb_disable_local_auth', 0) == 1 )
{
  $plugins->attachHook('ucp_register_validate', 'kerb_auth_reg_block($error);');
}

function kerb_auth_reg_block(&$error)
{
  $error = 'Registration on this website is disabled because Kerberos authentication is configured. Please log in using a valid Kerberos principal (username) and password, and an account will be created for you automatically.';
}

//
// ADMIN
//

$plugins->attachHook('session_started', 'kerb_session_hook();');

if ( getConfig('kerb_disable_local_auth', 0) == 1 )
{
  $plugins->attachHook('common_post', 'kerb_tou_hook();');
}

function kerb_session_hook()
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  // Register the admin page
  $paths->addAdminNode('adm_cat_security', 'Kerberos Authentication', 'KerberosConfig');
  
  // Disable password change
  if ( getConfig('kerb_disable_local_auth', 0) == 1 && $session->user_level < USER_LEVEL_ADMIN )
  {
    $link_text = getConfig('kerb_password_text', false);
    if ( empty($link_text) )
      $link_text = false;
    $link_url = str_replace('%u', $session->username, getConfig('kerb_password_url', ''));
    if ( empty($link_url) )
      $link_url = false;
    $session->disable_password_change($link_url, $link_text);
  }
}

function kerb_tou_hook()
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  // Are we pending TOU acceptance?
  if ( $session->user_logged_in && !$session->on_critical_page() && trim(getConfig('register_tou', '')) != '' )
  {
    $q = $db->sql_query('SELECT account_active FROM ' . table_prefix . "users WHERE user_id = $session->user_id;");
    if ( !$q )
      $db->_die();
    
    list($active) = $db->fetchrow_num();
    $db->free_result();
    if ( $active == 1 )
    {
      // Pending TOU accept
      // Basically, what we do here is force the user to accept the TOU and record it by setting account_active to 2 instead of a 1
      // A bit of a hack, but hey, it works, at least in 1.1.8.
      // In 1.1.7, it just breaks your whole account, and $session->on_critical_page() is broken in 1.1.7 so you won't even be able
      // to go the admin CP and re-activate yourself. Good times... erhm, sorry.
      
      if ( isset($_POST['tou_agreed']) && $_POST['tou_agreed'] === 'I accept the terms and conditions displayed on this site' )
      {
        // Accepted
        $q = $db->sql_query('UPDATE ' . table_prefix . "users SET account_active = 2 WHERE user_id = $session->user_id;");
        if ( !$q )
          $db->_die();
        
        return true;
      }
      
      global $output, $lang;
      $output->set_title('Terms of Use');
      $output->header();
      
      ?>
      <p>Please read and accept the following terms:</p>
      
      <div style="border: 1px solid #000000; height: 300px; width: 60%; clip: rect(0px,auto,auto,0px); overflow: auto; background-color: #FFF; margin: 0 auto; padding: 4px;">
        <?php
        $terms = getConfig('register_tou', '');
        echo RenderMan::render($terms);
        ?>
      </div>
      
      <form method="post">
        <p style="text-align: center;">
          <label>
            <input tabindex="7" type="checkbox" name="tou_agreed" value="I accept the terms and conditions displayed on this site" />
            <b><?php echo $lang->get('user_reg_lbl_field_tou'); ?></b>
          </label>
        </p>
        <p style="text-align: center;">
          <input type="submit" value="Continue" />
        </p>
      </form>
      
      <?php
      
      $output->footer();
      
      $db->close();
      exit;
    }
  }
}

function page_Admin_KerberosConfig()
{
  // Security check
  global $db, $session, $paths, $template, $plugins; // Common objects
  if ( $session->auth_level < USER_LEVEL_ADMIN )
    return false;

  require_once(ENANO_ROOT . '/plugins/kerbauth/libkrb5.php');
  
  if ( isset($_POST['submit']) )
  {
    setConfig('kerb_enable', isset($_POST['kerb_enable']) ? '1' : '0');
    setConfig('kerb_realm', $_POST['kerb_realm']);
    setConfig('kerb_admin_server', $_POST['kerb_admin_server']);
    setConfig('kerb_disable_local_auth', isset($_POST['kerb_disable_local_auth']) ? '1' : '0');
    setConfig('kerb_password_text', $_POST['kerb_password_text']);
    setConfig('kerb_password_url', $_POST['kerb_password_url']);
    setConfig('kerb_email_domain', $_POST['kerb_email_domain']);
    
    echo '<div class="info-box">Your changes have been saved.</div>';
  }
  
  acp_start_form();
  ?>
  <div class="tblholder">
    <table border="0" cellspacing="1" cellpadding="4">
      <tr>
        <th colspan="2">
          Kerberos Authentication Configuration
        </th>
      </tr>
      
      <!-- Kerberos enable -->
      
      <tr>
        <td class="row2" style="width: 50%;">
          Enable Kerberos authentication:
        </td>
        <td class="row1" style="width: 50%;">
          <label>
            <input type="checkbox" name="kerb_enable" <?php if ( getConfig('kerb_enable', 0) ) echo 'checked="checked" '; ?>/>
            Enabled
          </label>
        </td>
      </tr>
      
      <!-- Realm -->
      
      <tr>
        <td class="row2">
          Kerberos realm:<br />
          <small>Case sensitive.
          			<?php
          			if ( $realm = krb5_get_realm() )
          			{
          				echo "Leave blank to use auto-detected value: <b>$realm</b>";
          			}
          			?></small>
        </td>
        <td class="row1">
          <input type="text" name="kerb_realm" value="<?php echo htmlspecialchars(getConfig('kerb_realm', '')); ?>" size="40" />
        </td>
      </tr>
      
      <!-- Server -->
      
      <tr>
        <td class="row2">
          Kerberos admin server:<br />
          <small>This should be your admin server, not KDC. We're working on getting true KDC support enabled.
				  <?php
          			if ( $server = krb5_detect_admin_server(getConfig('kerb_realm', $realm)) )
          			{
          				echo "Leave blank to use auto-detected value: <b>$server</b>";
          			}
          			?></small>
        </td>
        <td class="row1">
          <input type="text" name="kerb_admin_server" value="<?php echo htmlspecialchars(getConfig('kerb_admin_server', '')); ?>" size="40" />
        </td>
      </tr>
      
      <!-- Block local auth -->
      
      <tr>
        <td class="row2">
          Enforce Kerberos for single-sign-on:<br />
          <small>Use this option to force Kerberos passwords and accounts to be used, regardless of local account status, except for administrators.</small>
        </td>
        <td class="row1">
          <label>
            <input type="checkbox" name="kerb_disable_local_auth" <?php if ( getConfig('kerb_disable_local_auth', 0) ) echo 'checked="checked" '; ?>/>
            Enabled
          </label>
        </td>
      </tr>
      
      <!-- E-mail domain -->
      
      <tr>
        <td class="row2">
          E-mail address domain for autoregistered users:<br />
          <small>When a user is automatically registered, this domain will be used as the domain for their e-mail address. This way, activation e-mails will
                 (ideally) reach the user.</small>
        </td>
        <td class="row1">
          <input type="text" name="kerb_email_domain" value="<?php echo htmlspecialchars(getConfig('kerb_email_domain', '')); ?>" size="30" />
        </td>
      </tr>
      
      <!-- Site password change link -->
      
      <tr>
        <td class="row2">
          External password management link:<br />
          <small>Enter a URL here to link to from Enano's Change Password page. Leave blank to not display a link. The text "%u" will be replaced with the user's username.</small>
        </td>
        <td class="row1">
          Link text: <input type="text" name="kerb_password_text" value="<?php echo htmlspecialchars(getConfig('kerb_password_text', '')); ?>" size="30" /><br />
          Link URL:  <input type="text" name="kerb_password_url" value="<?php echo htmlspecialchars(getConfig('kerb_password_url', '')); ?>" size="30" />
        </td>
      </tr>
      
      <tr>
        <th class="subhead" colspan="2">
          <input type="submit" name="submit" value="Save changes" />
        </th>
      </tr>
    </table>
  </div>
  <?php
  echo '</form>';
}
