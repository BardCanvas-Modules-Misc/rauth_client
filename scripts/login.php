<?php
/**
 * Login with expirable token
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var string "token"
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
    array('{$url}' => "{$config->full_root_url}?show_login_form=true")
));

$account = new account($id_account);

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

header("Location: {$config->full_root_url}");
die("<a href='{$config->full_root_url}'>{$language->click_here_to_continue}</a>");
