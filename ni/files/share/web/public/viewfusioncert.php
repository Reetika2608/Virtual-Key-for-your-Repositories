<?php
require_once( getenv("PHP_LIBDIR") . "/errorfactory.php" );
require_once( getenv("PHP_LIBDIR") . "/getfilecontents.php" );
require_once( getenv("PHP_LIBDIR") . "/securitycheck.php" );

perform_security_check();
$use_fingerprint = false;
$ca_path = '/mnt/harddisk/persistent/fusion/certs/fusion.pem';

if(isset($_GET['cert']))
{
    switch ($_GET['cert'])
    {
        case 'FUSION_CERTIFICATE':
            $file_exists = true;
            $file_alias = $_GET['cert'];

            $use_fingerprint = false;
            if (isset($_GET['fingerprint']))
            {
                $fingerprint = base64_decode($_GET['fingerprint']);
                $use_fingerprint = true;
            }

            break;
        default:
            $file_exists = false;
            break;
    }
}

if($file_exists)
{
    echo '<pre>';
    // The parser will go through the file and print
    // each item in the file.
    $parser = new CertificateParser(file_get_contents($ca_path));
    if ($use_fingerprint)
    {
        foreach ($parser->get_all() as $item)
        {
            if ($item->get_fingerprint() === $fingerprint)
            {
                // Found the one we want
                echo htmlspecialchars($item->getReadableText());
                break;
            }
        }
    }
    else
    {
        // Not interested in a specific entry so dump the whole file
        foreach ($parser->get_all() as $item)
        {
            echo htmlspecialchars($item->getReadableText()) . "\n";
        }
    }
    echo '</pre>';
    die();
}
$errorFactory = new Errorfactory();
SystemFileDisplay::fileNotFound($errorFactory);

?>
