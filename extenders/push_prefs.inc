<?php
/**
 * Accounts extender: push preferences to rauth server.
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 */

global $xaccount, $errors, $messages;

use hng2_modules\rauth_client\server;

try
{
    $server = new server();
}
catch(\Exception $e)
{
    $errors[] = $e->getMessage();
    
    return;
}

if( in_array($xaccount->user_name, $server->local_accounts) ) return;

$id    = $xaccount->id_account;
$prefs = $xaccount->engine_prefs;

try
{
    $server->push_engine_prefs($id, $prefs);
}
catch(\Exception $e)
{
    $errors[] = $e->getMessage();
    
    return;
}

if( is_array($messages) )
    $messages[] = replace_escaped_objects(
        $this_module->language->messages->prefs_pushed_ok,
        array('{$server}' => $server->auth_server_title)
    );
