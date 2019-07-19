<?php
/**
 * Accounts extender: level change
 * Allows changing user level on local accounts. On remote accounts it throws an error.
 * 
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 */

use hng2_modules\rauth_client\server;

global $user_account;

try
{
    $server = new server();
}
catch(\Exception $e)
{
    return;
}

if( in_array($user_account->user_name, $server->local_accounts) ) return;

die(replace_escaped_objects(
    $this_module->language->messages->no_level_change_allowed,
    array('{$server}' => $server->auth_server_title)
));
