<?php
/**
 * Remote account activation
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @param number "id_account" ENCRYPTED
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

if( ! is_numeric($id_account) ) die($current_module->language->messages->invalid_account_id);

$account = new account($id_account);

if( ! $account->_exists ) die($current_module->language->messages->missing_account);
if( $account->state != "new" ) die("OK");
if( $account->level >= $config::NEWCOMER_USER_LEVEL ) die("OK");

try
{
    $account->activate($config::NEWCOMER_USER_LEVEL);
}
catch( Exception $e )
{
    die($e->getMessage());
}

echo "OK";
