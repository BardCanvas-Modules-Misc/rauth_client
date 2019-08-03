<?php
/**
 * Remote account prefs saving
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * $_POST params:
 * @param number "id_account" ENCRYPTED
 * @param array  "prefs"      ENCRYPTED SERIALIZED
 * 
 * @return string "OK" or error message
 */

use hng2_base\account;
use hng2_modules\rauth_client\server;

include "../../config.php";
include "../../includes/bootstrap.inc";
header("Content-Type: text/plain; charset=utf-8");

$id_account = trim(stripslashes($_POST["id_account"]));
if( empty($id_account) ) die($current_module->language->messages->missing_account_id);

$raw_prefs = trim(stripslashes($_POST["prefs"]));
if( empty($raw_prefs) ) die($current_module->language->messages->missing_prefs);

try
{
    $server = new server();
}
catch(\Exception $e)
{
    die($e->getMessage());
}

$id_account = unserialize(three_layer_decrypt(
    $id_account, $server->auth_server_encryption_key1, $server->auth_server_encryption_key2, $server->auth_server_encryption_key3
));

$incoming_prefs = unserialize(three_layer_decrypt(
    $raw_prefs, $server->auth_server_encryption_key1, $server->auth_server_encryption_key2, $server->auth_server_encryption_key3
));

if( ! is_numeric($id_account) )   die($current_module->language->messages->invalid_account_id);
if( ! is_array($incoming_prefs) ) die($current_module->language->messages->invalid_prefs);

$zaccount = new account($id_account);
if( ! $zaccount->_exists ) die($current_module->language->messages->missing_account);

$pref_keys = array_unique(array_merge(array_keys($zaccount->engine_prefs), array_keys($incoming_prefs)));
foreach($pref_keys as $key)
{
    $val = isset($incoming_prefs[$key]) ? $incoming_prefs[$key] : "";
    $zaccount->set_engine_pref($key, $val);
}

send_notification($zaccount->id_account, "info", replace_escaped_objects(
    unindent($current_module->language->messages->received_prefs),
    array('{$server}' => $server->auth_server_title)
));
echo "OK";
