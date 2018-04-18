<?php
require_once( getenv("PHP_LIBDIR") . "/ajax_page.php" );
require_once( getenv("PHP_LIBDIR") . "/fusionstatustable.php" );
require_once( getenv("PHP_LIBDIR") . "/webuser.php");

class FusionAjax extends AjaxPage 
{
    protected function writeContent()
    {
        $status = new FusionStatus($this->rest_data_adapter);
        $status->renderRawDataOnly();
    }
}


$page = new FusionAjax();
$page->render();
?>
