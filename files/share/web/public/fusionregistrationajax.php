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

    private function is_bootstrap_data_present() {
        $root = $this->rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_tempTargetOrgId");
        return (int)$root->num_recs > 0 && $root->record[0]->value != '';
    }

    protected function writeContent()
    {
        // fake the box looking like an expressway if no release key
        $proxy_configured = $this->is_proxy_configured();


        if ( !$this->is_bootstrap_data_present() )
        {
            $registration_form = FusionLib::create_goto_cloud_form();
        }
        else
        {
            $prevent_upgrade_record = $this->rest_data_adapter->get_local("configuration/cafe/cafestaticconfiguration/name/c_mgmt_config_preventMgmtConnUpgrade");
            $prevent_upgrade = false;
            if (isset($prevent_upgrade_record) && (int)$prevent_upgrade_record->num_recs > 0)
            {
                if ((string)$prevent_upgrade_record->record[0]->value === "on")
                {
                    $prevent_upgrade = true;
                }
            }
            $on_latest = FusionLib::on_latest_c_mgmt($this->rest_data_adapter);
            if ( $prevent_upgrade || $on_latest ) {
                $registration_form = FusionLib::create_register_form();
            }
            else
            {
                $registration_form = FusionLib::create_bootstrap_form();
            }
        }
        $registration_form->render(); 
    }
}

$page = new PrecheckPage();
$page->render();

?>
