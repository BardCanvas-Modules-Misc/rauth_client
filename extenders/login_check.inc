<?php
/**
 * Accounts extender: login check
 * Performs local account validation and compares against the remote auth server
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 */

use hng2_base\account;
use hng2_modules\rauth_client\server;

global $account, $settings;

try
{
    $server = new server();
}
catch(\Exception $e)
{
    return;
}

if( in_array($account->user_name, $server->local_accounts) ) return;

if( $settings->get("engine.enabled") != "true" && ! $account->_is_admin )
    die("ERROR_ENGINE_DISABLED");

$user_name     = trim(stripslashes($_POST["user_name"]));
$password_hash = md5(trim(stripslashes($_POST["password"])));

#
# Validate existing account
#

if( $account->_exists )
{
    if( $account->state == "new" )
    {
        try
        {
            $server->send_new_account_confirmation_email($account->id_account);
        }
        catch(\Exception $e)
        {
            die("[ERROR] {$e->getMessage()}");
        }
        
        die("ERROR_UNCONFIRMED_ACCOUNT");
    }
    
    try
    {
        $server->validate_login($account->user_name, $password_hash);
    }
    catch(\Exception $e)
    {
        die("[ERROR] {$e->getMessage()}");
    }
    
    if( $account->password != $password_hash )
    {
        $account->password = $password_hash;
        $account->save();
    }
    
    return;
}

#
# Transfer unexistent account from remote auth server.
#

try
{
    $xaccount = $server->get_account($user_name, $password_hash);
}
catch(\Exception $e)
{
    die("[ERROR] {$e->getMessage()}");
}

$xaccount->_exists = false;
$xaccount->save();

$prefs = $xaccount->engine_prefs;
if( is_array($prefs) )
    foreach($prefs as $key => $val)
        $xaccount->set_engine_pref($key, $val);

$account = new account($xaccount->id_account);
