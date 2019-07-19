<?php
/**
 * Remote account level change
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @param number "id_account" ENCRYPTED
 * @param number "level"      ENCRYPTED
 * 
 * @return string "OK" or error message
 */

use hng2_base\account;
use hng2_modules\rauth_client\server;

include "../../config.php";
include "../../includes/bootstrap.inc";
header("Content-Type: text/plain; charset=utf-8");

$id_account = trim(stripslashes($_GET["id_account"]));
if( empty($id_account) ) die($current_module->language->messages->missing_account_id);

$level = trim(stripslashes($_GET["level"]));
if( empty($level) ) die($current_module->language->messages->missing_level);

try
{
    $server = new server();
}
catch(\Exception $e)
{
    die($e->getMessage());
}

$id_account = three_layer_decrypt(
    $id_account, $server->auth_server_encryption_key1, $server->auth_server_encryption_key2, $server->auth_server_encryption_key3
);

$level = three_layer_decrypt(
    $level, $server->auth_server_encryption_key1, $server->auth_server_encryption_key2, $server->auth_server_encryption_key3
);

if( ! is_numeric($id_account) ) die($current_module->language->messages->invalid_account_id);
if( ! is_numeric($level) )      die($current_module->language->messages->invalid_level);

$account = new account($id_account);

if( ! $account->_exists ) die($current_module->language->messages->missing_account);

if( $account->level == $level ) die("OK");

$account->set_level($level);

echo "OK";
