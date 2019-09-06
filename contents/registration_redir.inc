<?php
/**
 * Accounts extender: registration redirection
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 */

global $config, $settings, $account;

if( $account->_exists ) return;
if( $settings->get("modules:rauth_client.login_type") != "remote" ) return;
if( stristr($_SERVER["PHP_SELF"], "/accounts/register.php") === false ) return;

$website_name  = $settings->get("engine.website_name");
$server_name   = $settings->get("modules:rauth_client.auth_website_name");
$server_url    = $settings->get("modules:rauth_client.auth_server_url");
$client_handle = $settings->get("modules:rauth_client.auth_website_handle");

$registration_url = "{$server_url}/accounts/register.php?rauth_client_handle={$client_handle}";
header("Location: $registration_url");
die("<html><body><a href='$registration_url'>{$language->click_here_to_continue}</a></html>");
