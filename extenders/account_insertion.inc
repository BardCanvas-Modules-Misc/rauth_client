<?php
/**
 * Accounts extender: registration->before_insertion on accounts/register.php.
 * Note: this extender breaks the standard registration procedure!
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 */

global $config, $database, $mem_cache, $object_cache, $settings;
global $modules, $current_module, $template, $errors, $xaccount, $account;

use hng2_base\account;
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

$creation_ip             = get_remote_address();
$creation_host           = @gethostbyaddr($creation_ip);
$xaccount->creation_host = "$creation_ip; $creation_host";

# $errors[] = print_r($xaccount, true); return;

try
{
    $res = $server->register_account($xaccount);
}
catch(\Exception $e)
{
    $errors[] = sprintf(
        $this_module->language->messages->registration_error, $server->auth_server_title, $e->getMessage()
    );
    
    return;
}

if( is_null($res) )
{
    $errors[] = sprintf(
        $this_module->language->messages->null_remote_object, $server->auth_server_title
    );
    
    return;
}

#
# Save and exit.
#

$xaccount = new account($res);
$xaccount->_exists = false;
$xaccount->save();

$current_module = $modules["accounts"];
$account        = new account();

if( ! empty($_REQUEST["redir_url"]) )
{
    header("Location: " . $_REQUEST["redir_url"]);
    die("<a href='".$_REQUEST["redir_url"]."'>".$current_module->language->click_to_continue."</a>");
}

$template->set_page_title($current_module->language->page_titles->registration_form_submitted);
$template->page_contents_include = "register_form_submitted.tpl.inc";
include "{$template->abspath}/main.php";
die();
