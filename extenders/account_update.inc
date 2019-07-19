<?php
/**
 * Accounts extender: profile_editor->before_saving on accounts/edit_account.php.
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 */

global $xaccount, $account, $errors, $messages;

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

if( in_array($account->user_name, $server->local_accounts) ) return;

try
{
    $server->update_account($xaccount);
}
catch(\Exception $e)
{
    $errors[] = $e->getMessage();
    
    return;
}

if( is_array($messages) )
    $messages[] = replace_escaped_objects(
        $this_module->language->messages->account_pushed_ok,
        array('{$server}' => $server->auth_server_title)
    );
