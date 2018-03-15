<?php
require_once( getenv("PHP_LIBDIR") . "/getfilecontents.php" );
if (file_exists(getenv("PHP_LIBDIR") . "/product.php")) {
    require_once( getenv("PHP_LIBDIR") . "/product.php" );
}else{
    require_once( getenv("PHP_LIBDIR") . "/productbase.php" );
    class Product extends ProductBase {} 
}
require_once( getenv("PHP_LIBDIR") . "/adminuser.php" );
require_once( getenv('PHP_LIBDIR') . '/systemfile.php' );
require_once( getenv("PHP_LIBDIR") . "/errorfactory.php" );
require_once( getenv("PHP_LIBDIR") . "/i18n.php" );
require_once( getenv("PHP_LIBDIR") . "/securitycheck.php" );


perform_security_check();
$errorFactory = new Errorfactory();

if ( isset( $_GET['file'] ) )
{
    if( $_GET['file'] === "FUSION_CERTIFICATE" )
    {
        $ca_path = '/mnt/harddisk/persistent/fusion/certs/fusion.pem';

        $ca_file = new SystemFile('FUSION_CERTIFICATE',
                                        'text', false, 'PEM File' );

        $ca_file->set_content(file_get_contents($ca_path));
        $ca_file->set_size(filesize($ca_path));

        $page = new SystemFileDisplay( $ca_file, $errorFactory );
        $page->render();
        die();
    }
}

SystemFileDisplay::fileNotFound($errorFactory);

?>
