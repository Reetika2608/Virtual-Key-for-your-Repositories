<?php
require_once( getenv("PHP_LIBDIR") . "/ajax_page.php" );
require_once( getenv("PHP_LIBDIR") . "/cafejsonbloblib.php" );
require_once( getenv("PHP_LIBDIR") . "/fusionlib.php" );

require_once( getenv("PHP_LIBDIR") . "/widgets/hyperlink.php" );
require_once( getenv("PHP_LIBDIR") . "/widgets/label.php" );
require_once( getenv("PHP_LIBDIR") . "/widgets/tickbox.php" );
require_once( getenv("PHP_LIBDIR") . "/widgets/hyperlink.php" );
require_once( getenv("PHP_LIBDIR") . "/widgets/textwithhyperlinks.php");
require_once( getenv("PHP_LIBDIR") . "/widgets/statuswidget.php" );

require_once( getenv("PHP_LIBDIR") . "/dataform.php" );

class PrecheckPage extends AjaxPage 
{
    private function is_proxy_configured()
    {
        $root = $this->rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_https_proxy");

        $blob_name = "c_mgmt_https_proxy";
        $data = BlobLibrary::get_one($this->rest_data_adapter, $blob_name);

        if($data && isset($data['enabled']))
        {
            return $data['enabled'] == "true";
        }

        return false;
    }

    protected function writeContent()
    {
        // fake the box looking like an expressway if no release key
        $proxy_configured = $this->is_proxy_configured();

        $server_visible = true;
        $certs_good = false;
        $precheck_run = false;

        // get service urls from u2c
        FusionLib::update_service_catalog($this->rest_data_adapter);

        // run precheck xcommand
        list($precheck_run, $precheck_info) = BlobLibrary::run_xcommand($this->rest_data_adapter, "c_mgmt", "precheck", array());
        if($precheck_run)
        {
	        switch($precheck_info)
	        {
	            case 'Not_found':
	                $server_visible = false;
	                $certs_good = false;
	                break;
	            case 'Found_bad_certs':
                    $server_visible = true;
	                $certs_good = false;
	                break;
	            case 'Found_good_certs':
	                // everythings great
                    $server_visible = true;
                    $certs_good = true;
	                break;
	            case 'Unchecked':
	            default:
                    $precheck_run = false;
	                break;
	        }
	    }

        $peer_data = $this->IProduct->get_peerdata();

        $registration_form = FusionLib::create_registration_form(
                                        $peer_data, $precheck_run,
                                        $server_visible, $certs_good, $proxy_configured);
        $registration_form->render(); 
    }
}

$page = new PrecheckPage();
$page->render();

?>
