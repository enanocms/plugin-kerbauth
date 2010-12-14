<?php

class KerberosError extends Exception
{
}

/**
 * Parse an INI file, specifically one in krb5.conf format.
 * @param string File to read
 * @return array
 */

function krb5_read_ini_file($file)
{
	$fp = @fopen($file, 'r');
	if ( !$fp )
		return array();
	$section = '';
	$data = array();
	
	while ( !feof($fp) )
	{
		// read in line
		$line = @fgets($fp, 8192);
		
		// trim and skip comments
		$line = trim(preg_replace('/;.*$/', '', $line));
		if ( empty($line) )
			continue;
		
		if ( preg_match('/^\[(.+?)\]$/', $line, $match) )
		{
			// new section
			$section = $match[1];
			continue;
		}
		if ( count($parts = explode('=', $line)) == 2 )
		{
			list($name, $value) = $parts;
		}
		else
		{
			$name = $line;
			$value = true;
		}
		$name = trim($name);
		// ltrim to honor trailing spaces/tabs
		$value = ltrim($value);
		if ( $value === '{' )
		{
			$section .= ".$name";
			$subsection = $name;
			continue;
		}
		else if ( $name === '}' && isset($subsection) )
		{
			$section = substr($section, 0, strlen($section) - 1 - strlen($subsection));;
			continue;
		}
		if ( !empty($section) )
		{
			$name = "$section.$name";
		}
		if ( $value === 'true' )
			$value = true;
		else if ( $value === 'false' )
			$value = false;
		else if ( ctype_digit($value) )
			$value = intval($value);
		$data[$name] = $value;
	}
	fclose($fp);
	return $data;
}

function krb5_get_config()
{
	static $config = false;
	if ( @file_exists('/etc/krb5.conf') && @is_readable('/etc/krb5.conf') )
		return $config = krb5_read_ini_file('/etc/krb5.conf');
	
	return false;
}

function krb5_get_realm()
{
	if ( $config = krb5_get_config() )
	{
		if ( isset($config['libdefaults.default_realm']) )
		{
			return $config['libdefaults.default_realm'];
		}
	}
	return false;
}

function krb5_detect_admin_server($realm = '__default__')
{
	if ( $config = krb5_get_config() )
	{
		if ( isset($config['libdefaults.default_realm']) )
		{
			$realm = ($realm == '__default__') ? $config['libdefaults.default_realm'] : $realm;
			// we have the default realm; determine what the admin server is
			if ( isset($config["realms.$realm.admin_server"]) )
			{
				return $config["realms.$realm.admin_server"];
			}
			// failing ini parsing, honor dns_lookup_kdc (this isn't strictly looking up KDCs, more the master, but this allows for configurability)
			if ( isset($config['libdefaults.dns_lookup_kdc']) && $config['libdefaults.dns_lookup_kdc'] && function_exists('dns_get_record') )
			{
				// look it up
				$dns_result = dns_get_record('_kerberos-master._udp.' . strtolower($realm), DNS_SRV);
				// find result with lowest priority
				$host = '';
				$pri = 0x7FFFFFFF;
				if ( $dns_result )
				{
					foreach ( $dns_result as $entry )
					{
						if ( $entry['pri'] < $pri )
						{
							$host = $entry['target'];
						}
					}
					if ( !empty($host) )
					{
						return $host;
					}
				}
			}
		}
	}
	return false;
}

function krb5_verify_creds($username, $password)
{
	$realm = getConfig('kerb_realm', krb5_get_realm());
	$server = getConfig('kerb_admin_server', krb5_detect_admin_server($realm));
	
	if ( empty($realm) || empty($server) )
		throw new KerberosError("Empty realm or server");
	
	$result = kadm5_init_with_password($server, $realm, $username, $password);
	if ( $result === FALSE )
	{
		return FALSE;
	}
	@kadm5_destroy($result);
	return TRUE;
}

