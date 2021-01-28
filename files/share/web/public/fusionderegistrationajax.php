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

class DeregPage extends AjaxPage 
{
    protected function writeContent()
    {
        // fake the box looking like an expressway if no release key
        $this->IProduct->force_refer_to_expressway = true;
        Internationalisation::add_special_tag_translations(
            $this->IProduct->get_special_i18n_tags());

        BlobLibrary::run_xcommand($this->rest_data_adapter, "c_mgmt", "deregistered_check", array());

        $registration_form = FusionLib::create_goto_cloud_form($this->rest_data_adapter, $this->IProduct->isExpresswayEnabled());
        $registration_form->render(); 
    }
}

$page = new DeregPage();
$page->render();

?>
