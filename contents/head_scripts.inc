<?php
/**
 * Accounts extender: scripts and styles
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 */

global $config, $settings, $account;

if( $account->_exists ) return;
if( $settings->get("modules:rauth_client.login_type") != "remote" ) return;

$server_name      = $settings->get("modules:rauth_client.auth_website_name");
$server_url       = $settings->get("modules:rauth_client.auth_server_url");
$client_handle    = $settings->get("modules:rauth_client.auth_website_handle");
$return_to        = urlencode($_SERVER["REQUEST_URI"]);
$registration_url = "{$server_url}/accounts/register.php?wsh={$client_handle}&redir_url={$return_to}";

$config->globals["@accounts:login_form.registration_page_url_override"] = $registration_url;
?>

<!-- Remote Auth Client scripts and styles -->

<style type="text/css">
    #sidebar_login_form .registration_link              { display: none; }
    #sidebar_login_form .field.standard_user_name       { display: none; }
    #sidebar_login_form .field.standard_password        { display: none; }
    #sidebar_login_form .field.standard_password_reset  { display: none; }
    #sidebar_login_form .field.submit_button_container  { display: none; }

    #sidebar_login_form .rauth_client_login_with { font-size: 1.2em; line-height: normal;
                                                   margin-bottom: 5px;  text-align: center; }
    #sidebar_login_form .rauth_local_login_link  { font-size: 0.8em; line-height: normal;
                                                   text-align: center; }
    
    #sidebar_login_form.with_local_login .registration_link              { display: inline; }
    #sidebar_login_form.with_local_login .field.standard_user_name       { display: block;  }
    #sidebar_login_form.with_local_login .field.standard_password        { display: block;  }
    #sidebar_login_form.with_local_login .field.standard_password_reset  { display: block;  }
    #sidebar_login_form.with_local_login .field.submit_button_container  { display: block;  }
    #sidebar_login_form.with_local_login .rauth_client_login_with        { display: none; }
    #sidebar_login_form.with_local_login .rauth_local_login_link         { display: none; }
    
    #login_dialog #login_form                                 { width: 100%; }
    #login_dialog #login_form .field.standard_user_name       { display: none; }
    #login_dialog #login_form .field.standard_password        { display: none; }
    #login_dialog #login_form .field.standard_password_reset  { display: none; }
    #login_dialog #login_form .field.submit_button_container  { display: none; }
    
    #login_dialog #login_form .rauth_client_login_with { font-size: 1.2em; line-height: normal; margin-bottom: 5px;
                                                         text-align: center; width: 100%; margin-top: 0; }
    
    #login_dialog #login_form.with_local_login .field.standard_user_name       { display: block; }
    #login_dialog #login_form.with_local_login .field.standard_password        { display: block; }
    #login_dialog #login_form.with_local_login .field.standard_password_reset  { display: block; }
    #login_dialog #login_form.with_local_login .field.submit_button_container  { display: block; }
    #login_dialog #login_form.with_local_login .rauth_client_login_with        { display: none;  }
    #login_dialog #login_form.with_local_login .rauth_local_login_link         { display: none;  }
</style>
