<?php
require_once( getenv("PHP_LIBDIR") . "/eventlogbase.php" );

$log_path = "/mnt/harddisk/log/hybrid_services_log";

// Check whether this page is on the Experimental page or not.
$page = new EventLogPage($log_path, "hybridservicesloglevels", "hybridserviceslog");
$page->render();

?>
