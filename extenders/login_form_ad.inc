<?php
/**
 * Accounts extender: ad on top of login form
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 */

global $config, $settings;

use hng2_modules\rauth_client\server;

try
{
    $server = new server();
}
catch(\Exception $e)
{
    return;
}

#
# Using local always
#

if( $settings->get("modules:rauth_client.login_type") != "remote" ): ?>
    
    <!-- Remote auth login invitation -->
    
    <span class="framed_content rauth_login_ad state_ok"
       style="display: block; margin-top: 0; margin-bottom: 10px; text-align: center; line-height: normal;">
        <?= replace_escaped_objects(
            $this_module->language->login_using_rauth, array(
                '{$server_url}'  => $server->auth_server_url,
                '{$server_name}' => $server->auth_server_title,
            )) ?>
    </span>
    
    <? return;
endif;

#
# Using remote always
#

if( $settings->get("modules:rauth_client.login_type") != "remote" ) return;

$server_name   = $settings->get("modules:rauth_client.auth_website_name");
$server_url    = $settings->get("modules:rauth_client.auth_server_url");
$client_handle = $settings->get("modules:rauth_client.auth_website_handle");
$return_to     = urlencode($_SERVER["REQUEST_URI"]);
$login_url     = "{$server_url}/rauth_login?wsh={$client_handle}&return_to={$return_to}";

$login_caption = $settings->get("modules:rauth_client.login_link_caption");
if( empty($login_caption) )
    $login_caption = replace_escaped_objects(
        $this_module->language->always_remote->login_caption,
        array('{$server_name}' => $server_name)
    );
?>

<!-- Remote Auth client overrides  -->

<div class="framed_content state_ok rauth_client_login_with pseudo_link"
     onclick="location.href = '<?= $login_url ?>'">
    <?= $login_caption ?>
</div>
<div class="rauth_local_login_link">
    <span class="pseudo_link" onclick="$(this).closest('form').toggleClass('with_local_login', true);">
        <i class="fa fa-sign-in"></i>
        <?= $this_module->language->always_remote->local_login ?>
    </span>
</div>
