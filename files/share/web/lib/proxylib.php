<?php
require_once( getenv("PHP_LIBDIR") . "/applicationpage.php" );
require_once( getenv("PHP_LIBDIR") . "/cafejsonbloblib.php" );
require_once( getenv("PHP_LIBDIR") . "/hideshower.php" );

abstract class ProxyPage extends ApplicationPage 
{
    abstract protected function updateData();
    abstract protected function initForm();

    protected $form = false;  
    protected $regexs = array(
            "enabled" => '/^(true|false)$/',
            "address" => '/^[^"\']{1,50}$/', // probably should be ipv4 or ipv6 or fqdn
            "port" => "/^[0-9]{1,5}$/",
            "username" => '/^[^"\']{0,50}$/',
            "password" => '/^[^"\']{0,50}$/');

    protected $labels = array(
            "enabled" => "lbl.USE_FUSION_PROXY",
            "address" => "lbl.FUSION_PROXY_ADDRESS",
            "port" => "lbl.FUSION_PROXY_PORT",
            "username" => "lbl.FUSION_PROXY_USERNAME",
            "password" => "lbl.FUSION_PROXY_PASSWORD");

    protected $blob_name = "c_mgmt_https_proxy";
    protected $reload_from_postdata = false;

    public function get_page_title_for_help()
    {
        return "connectorproxy";
    }

    protected function init()
    {
        $this->updateData();
        $this->initForm();
        if ( $this->form )
        {
            $this->view->inline_javascript[] = $this->_get_javascript();
        }
    }

    function _get_javascript()
    {
        $js = '
        function validate(form)
        {
            if (validateIPOrHostNameWithPort(form.address, "lbl.FUSION_PROXY_ADDRESS"))
            {
                return valuespace_validation(form);
            }
            else
            {
                return false;
            }
        }';
        return $js;
    }
}
?>
