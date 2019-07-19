<?php
/**
 * Accounts extender: ad on top of login form
 *
 * @package    BardCanvas
 * @subpackage rauth_client
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 */

use hng2_modules\rauth_client\server;

try
{
    $server = new server();
}
catch(\Exception $e)
{
    return;
}
?>

<span class="framed_content state_ok"
   style="display: block; margin-top: 0; margin-bottom: 10px; text-align: center; line-height: normal;">
    <?= replace_escaped_objects(
        $this_module->language->login_using_rauth, array(
            '{$server_url}'  => $server->auth_server_url,
            '{$server_name}' => $server->auth_server_title,
        )) ?>
</span>
