<?php
require_once( getenv("PHP_LIBDIR") . "/loglevelbase.php" );

class DeveloperLogLevelPage extends LogLevelBasePage
{
    protected $source = "hybridserviceslogger";
    //We're hiding the loglevel developer as it covers all loggin and if turned on would grind the box to a halt. 
    function modify_row($rowData)
    {
        $nameIndex = "name";  // The index of the name column
        if($rowData[$nameIndex] == "hybridservices")
        {
            return NULL;
        }
        return $rowData;
    }
}

$page = new DeveloperLogLevelPage();
$page->render();
?>
