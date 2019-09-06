<?php
/**
 * Login with expirable token
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var string "token"
 * @var string "redirect_to" optional
 * @var string "uhash"       encrypted user name, optional, if provided, we're dealing with an account transfer
 * @var string "phash"       encrypted password hash, optional, if provided, we're dealing with an account transfer
 */

use hng2_base\account;
use hng2_base\device;
use hng2_modules\rauth_client\server;

include "../../config.php";
include "../../includes/bootstrap.inc";
header("Content-Type: text/html; charset=utf-8");

$token = trim(stripslashes($_GET["token"]));
if( empty($token) ) die($current_module->language->messages->missing_token);

try
{
    $server = new server();
}
catch(\Exception $e)
{
    die($e->getMessage());
}

$token = three_layer_decrypt(
    $token, $server->auth_server_encryption_key1, $server->auth_server_encryption_key2, $server->auth_server_encryption_key3
);

if( ! preg_match("/[0-9]+,[0-9]+/", $token) ) die($current_module->language->messages->invalid_token);

list($id_account, $expiration_timestamp) = explode(",", $token);

if( time() > $expiration_timestamp ) die(replace_escaped_objects(
    $current_module->language->messages->token_expired,
    array('{$link}' => "{$config->full_root_url}?show_login_form=true")
));

$account = new account($id_account);

#
# Transfer check
#

if( ! $account->_exists )
{
    if( ! empty($_GET["uhash"]) && ! empty($_GET["phash"]) )
    {
        $user_name = three_layer_decrypt(
            stripslashes($_GET["uhash"]),
            $server->auth_server_encryption_key1,
            $server->auth_server_encryption_key2,
            $server->auth_server_encryption_key3
        );
        $password_hash = three_layer_decrypt(
            stripslashes($_GET["phash"]),
            $server->auth_server_encryption_key1,
            $server->auth_server_encryption_key2,
            $server->auth_server_encryption_key3
        );
        
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
        $account = new account($xaccount->id_account);
        foreach($prefs as $key => $val) $account->set_engine_pref($key, $val);
    }
}

#
# Adapted snipped from accounts/scripts/login.php
#

if( ! $account->_exists )
    die($modules["accounts"]->language->errors->account_unexistent);

if( $account->state == "new" )
    die(unindent(replace_escaped_objects(
        $current_module->language->messages->account_unconfirmed,
        array('{$url}' => "{$config->full_root_url}?show_login_form=true")
    )));

if( $account->state != "enabled" )
    die($modules["accounts"]->language->errors->account_disabled);

if( $settings->get("engine.enabled") != "true" && ! $account->_is_admin )
    die($modules["accounts"]->language->errors->engine_disabled);

#==========================================#
# Session opening and new device detection #
#==========================================#

$device = new device($account->id_account);

if( $device->_exists && $device->state == "disabled" )
    die($modules["accounts"]->language->errors->device_disabled);

$device->set_new($account);
$device->state = "enabled";
$device->save();

$account->open_session($device);

$url = empty($_GET["redirect_to"]) ? $config->full_root_url : stripslashes($_GET["redirect_to"]);

header("Location: $url");
die("<a href='$url'>{$language->click_here_to_continue}</a>");
