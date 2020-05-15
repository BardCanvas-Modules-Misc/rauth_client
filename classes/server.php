<?php
namespace hng2_modules\rauth_client;

use hng2_base\account;

class server
{
    public $auth_website_handle;
    public $auth_server_title;
    public $auth_server_url;
    public $auth_server_encryption_key1;
    public $auth_server_encryption_key2;
    public $auth_server_encryption_key3;
    
    public $local_accounts = array();
    
    private $initialized = false;
    
    public function __construct()
    {
        global $settings, $modules;
        
        $current_module = $modules["rauth_client"];
        
        $this->auth_website_handle = $settings->get("modules:rauth_client.auth_website_handle");
        if( empty($this->auth_website_handle) )
            throw new \Exception(trim($current_module->language->messages->website_handle_empty));
        
        $this->auth_server_title = $settings->get("modules:rauth_client.auth_website_name");
        if( empty($this->auth_server_title) )
            throw new \Exception(trim($current_module->language->messages->website_name_empty));
        
        $this->auth_server_url = $settings->get("modules:rauth_client.auth_server_url");
        if( empty($this->auth_server_url) )
            throw new \Exception(trim($current_module->language->messages->website_url_empty));
        
        $keys = $settings->get("modules:rauth_client.auth_server_keys");
        if( empty($keys) )
            throw new \Exception(trim($current_module->language->messages->website_keys_incomplete));
        
        $keys = explode("\n", $keys);
        if( count($keys) != 3 )
            throw new \Exception(trim($current_module->language->messages->website_keys_incomplete));
        
        $this->auth_server_encryption_key1 = trim($keys[0]);
        $this->auth_server_encryption_key2 = trim($keys[1]);
        $this->auth_server_encryption_key3 = trim($keys[2]);
        
        $list = $settings->get("modules:rauth_client.local_accounts");
        if( ! empty($list) )
        {
            foreach(explode("\n", $list) as $line)
            {
                $line = trim($line);
                if( empty($line) ) continue;
                if( substr($line, 0, 1) == "#" ) continue;
                
                $this->local_accounts[] = $line;
            }
        }
        
        $this->initialized = true;
    }
    
    /**
     * @param account $xaccount
     *
     * @return object|null
     * @throws \Exception
     */
    public function register_account($xaccount)
    {
        if( ! $this->initialized ) return null;
        
        $res = $this->request("create_account", $xaccount);
        if( empty($res) ) return null;
        
        $object = unserialize(three_layer_decrypt(
            $res,
            $this->auth_server_encryption_key1,
            $this->auth_server_encryption_key2,
            $this->auth_server_encryption_key3
        ));
        
        if( ! is_object($object) ) return null;
        
        return $object;
    }
    
    /**
     * @param account $account
     * 
     * @return bool
     */
    public function is_local_account_mapped_remotely($account)
    {
        if( ! $this->initialized ) return false;
        
        return isset($account->engine_prefs["@rauth_client.mapped_account_id"]);
    }
    
    /**
     * @param account $account
     * @param int     $ttl_minutes
     *
     * @return string
     */
    public function tokenize_mapped_account_id($account, $ttl_minutes = 0)
    {
        if( ! $this->initialized ) return null;
        
        if( empty($ttl_minutes) ) return three_layer_encrypt(
            $account->engine_prefs["@rauth_client.mapped_account_id"],
            $this->auth_server_encryption_key1,
            $this->auth_server_encryption_key2,
            $this->auth_server_encryption_key3
        );
        
        return three_layer_encrypt(
            $account->engine_prefs["@rauth_client.mapped_account_id"] . "," . (time() + ($ttl_minutes * 60)),
            $this->auth_server_encryption_key1,
            $this->auth_server_encryption_key2,
            $this->auth_server_encryption_key3
        );
    }
    
    /**
     * @param account $xaccount
     *
     * @return account|null
     * @throws \Exception
     */
    public function map_local_account($xaccount)
    {
        if( ! $this->initialized ) return null;
        
        $res = $this->request("map_client_account", $xaccount);
        if( empty($res) ) return null;
        
        $object = unserialize(three_layer_decrypt(
            $res,
            $this->auth_server_encryption_key1,
            $this->auth_server_encryption_key2,
            $this->auth_server_encryption_key3
        ));
        
        if( ! is_object($object) ) return null;
        
        $xaccount->set_engine_pref("@rauth_client.mapped_account_id", $object->id_account);
        
        return $object;
    }
    
    /**
     * @param $id_account
     *
     * @throws \Exception
     */
    public function send_new_account_confirmation_email($id_account)
    {
        if( ! $this->initialized ) return;
        
        $data = array("id_account" => $id_account, "ip" => get_remote_address());
        $this->request("send_confirmation_email", $data);
    }
    
    /**
     * @param string $user_name
     * @param string $password_hash
     *
     * @throws \Exception
     */
    public function validate_login($user_name, $password_hash)
    {
        if( ! $this->initialized ) return;
    
        $params = array("user_name" => $user_name, "password_hash" => $password_hash);
        $this->request("validate_login", $params);
    }
    
    /**
     * @param string $user_name
     * @param string $password_hash
     *
     * @return account
     * @throws \Exception
     */
    public function get_account($user_name, $password_hash)
    {
        global $modules;
        $current_module = $modules["rauth_client"];
        
        if( ! $this->initialized ) return null;
        
        $params = array("user_name" => $user_name, "password_hash" => $password_hash);
        $res = $this->request("get_account", $params);
        
        if( empty($res) )
            throw new \Exception(trim($current_module->language->messages->invalid_object_returned));
        
        $object = unserialize(three_layer_decrypt(
            $res,
            $this->auth_server_encryption_key1,
            $this->auth_server_encryption_key2,
            $this->auth_server_encryption_key3
        ));
        
        if( ! is_object($object) )
            throw new \Exception(trim($current_module->language->messages->invalid_object_returned));
        
        return $object;
    }
    
    /**
     * @param account $xaccount
     * 
     * @throws \Exception
     */
    public function update_account($xaccount)
    {
        if( ! $this->initialized ) return;
        
        $this->request("update_account", $xaccount);
    }
    
    public function push_engine_prefs($id_account, $prefs)
    {
        if( ! $this->initialized ) return;
        
        $params = (object) array(
            "id_account" => $id_account,
            "prefs"      => $prefs,
        );
        
        $this->request("update_engine_prefs", $params);
    }
    
    /**
     * @param string $method
     * @param mixed  $params
     *
     * @return mixed
     * @throws \Exception
     */
    private function request($method, $params)
    {
        global $modules;
        
        $current_module = $modules["rauth_client"];
        
        $url       = "$this->auth_server_url/api/$method?wsh=$this->auth_website_handle";
        $post_data = http_build_query(array("data" => three_layer_encrypt(
            serialize($params),
            $this->auth_server_encryption_key1,
            $this->auth_server_encryption_key2,
            $this->auth_server_encryption_key3
        )));
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,            $url );
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_FRESH_CONNECT,  TRUE);
        curl_setopt($ch, CURLOPT_POSTFIELDS,     $post_data);
        
        usleep(100000);
        $contents = curl_exec($ch);
        # echo "\n$contents\n";
        
        if( curl_error($ch) )
            throw new \Exception(sprintf(
                $current_module->language->messages->remote_api_error, $url, curl_error($ch)
            ));
        
        curl_close($ch);
        
        if( empty($contents) )
            throw new \Exception(sprintf(
                $current_module->language->messages->remote_api_empty, $url
            ));
        
        $json = json_decode($contents);
        if( is_null($json) )
            throw new \Exception(sprintf(
                $current_module->language->messages->invalid_api_response, $contents, $url
            ));
        
        if( ! (is_object($json) || is_array($json)) )
            throw new \Exception(sprintf(
                $current_module->language->messages->invalid_api_object, $url
            ));
        
        if( $json->message != "OK" )
            throw new \Exception(sprintf(
                $current_module->language->messages->remote_auth_error, $json->message
            ));
        
        return $json->data;
    }
}
