<?php
require_once( getenv("PHP_LIBDIR") . "/ajax_page.php" );
require_once( getenv("PHP_LIBDIR") . "/fusionlib.php" );

class FusedcheckPage extends AjaxPage 
{
    protected function writeContent()
    {
        echo FusionLib::get_defused_state($this->rest_data_adapter);
    }
}

$page = new FusedcheckPage();
$page->render();

?>