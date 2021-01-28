<?php
require_once( getenv("PHP_LIBDIR") . "/applicationpage.php" );
require_once( getenv("PHP_LIBDIR") . "/fusionlib.php" );
require_once( getenv('PHP_LIBDIR') . '/systemfile.php' );
require_once( getenv("PHP_LIBDIR") . "/securitycertificatespagebase.php");
require_once( getenv("PHP_LIBDIR") . "/datatablewrapper.php");


class FusionCertPage extends SecurityCertificatesPageBase
{
    private $form = false;
    private $doc_id = "1936";
    private $caTable;
    private $certs = null;
    private $table_rows = array();
    private $blank = "-";
    protected $is_ca_deletion = false;


    protected function init()
    {
        $this->decoded_view_link_text = "btn.SHOW_ALL_HUMAN_READABLE";
        $ca_path = '/mnt/harddisk/persistent/fusion/certs/fusion.pem';

        $this->ca_file = new SystemFile('FUSION_CERTIFICATE',
                                        'text', false, 'PEM File' );

        if(file_exists($ca_path))
        {
            $this->ca_file->set_content(file_get_contents($ca_path));
            $this->ca_file->set_size(filesize($ca_path));
        }
        else
        {
            $this->ca_file->set_content("");
            $this->ca_file->set_size(0);
        }
        $this->obtainCertCheckingFlag();

        $this->updateData();

        if($this->IProduct->isExpresswayEnabled())
        {
            $this->addError(new InfoMessage(
                tt_gettext("err.NO_FUSION_ON_EXPRESSWAY_TITLE"),
                tt_gettext("err.NO_FUSION_ON_EXPRESSWAY")));
        }
        $this->initForm();
    }

    protected function get_decoded_view_link()
    {
        return sprintf("viewfusioncert?cert=%s", $this->ca_file->get_alias());
    }

    protected function get_download_view_link()
    {
        return sprintf("downloadfusion?file=%s", $this->ca_file->get_alias());
    }

    protected function get_download_link_text()
    {
        return sprintf(tt_gettext("btn.SHOW_ALL_FORMAT_%s"),  tt_gettext($this->ca_file->get_type()));
    }

    public function set_help_js()
    {
        if($this->IProduct->isExpresswayEnabled())
        {
            return parent::set_help_js();
        }
        else
        {
            return FusionLib::get_knowledge_base_js($this->doc_id);
        }
    }

    public function set_help_path()
    {
        if($this->IProduct->isExpresswayEnabled())
        {
            return parent::set_help_path();
        }
        else
        {
            return FusionLib::get_knowledge_base_url($this->doc_id);
        }
    }

    private function initForm()
    {
        $this->form = new DataForm( $_SERVER['REQUEST_URI'], "valuespace_validation" );
        $fieldset = $this->form->createFieldset("lbl.FUSION_CERT_FIELDSET");

        if(FusionLib::are_fusion_certs_installed())
        {
            // remove warning
            if($this->IProduct->isExpresswayEnabled())
            {
                $remove_cert_message = "lbl.EXPRESSWAY_FUSION_CERT_REMOVE_INSTRUCTIONS";
            }
            else
            {
                $remove_cert_message = "lbl.FUSION_CERT_REMOVE_INSTRUCTIONS";
            }
            $fieldset->addRow("", new Label(tt_gettext($remove_cert_message)));
            $button = $this->form->setSubmitButtonText("btn.REMOVE_FUSION_CERTS");
            $spinner_text = tt_gettext("lbl.REMOVING_FUSION_CERT");
        }
        else
        {
            // add warning
            if($this->IProduct->isExpresswayEnabled())
            {
                $add_cert_message = "lbl.EXPRESSWAY_FUSION_CERT_ADD_INSTRUCTIONS";
            }
            else
            {
                $add_cert_message = "lbl.FUSION_CERT_ADD_INSTRUCTIONS";
            }
            $fieldset->addRow("", new Label(tt_gettext($add_cert_message)));
            $button = $this->form->setSubmitButtonText("btn.ADD_FUSION_CERTS");
            $spinner_text = tt_gettext("lbl.ADDING_FUSION_CERT");
        }
        $button->add_on_click_handler("trigger_loader_gif('$spinner_text')");

        $fieldset->hide_labels();

        $this->view->inline_javascript[] = $this->form->get_valuespace_javascript( "valuespace_validation" );

        // Parse the existing trusted CA list
        $data = $this->ca_file->get_content();
        $parser = new CertificateParser($data);
        $this->cert_objects = $parser->get_all();
        $this->is_ca_deletion = false;


        //---------------------------------------------------------------------
        $this->build_certificate_details();

        $header_xpaths = array(
                "col.CERT_TYPE" => "type",
                "col.ISSUER" => "issuer",
                "col.SUBJECT" => "subject",
                "col.EXPIRATION" => "expires",
                "col.VALIDITY" => "validity",
                "col.VIEW" => "view" );

        $tableWithinForm = new DataTableWrapper($header_xpaths);

        $tableWithinForm->isTextLinkEnabled(false);
        $tableWithinForm->set_listing_only(true);
        $tableWithinForm->suppressDefaultActions();
        $tableWithinForm->initialise(count($this->table_rows));
        $tableWithinForm->add_rows($this->table_rows);

        if ( $this->ca_file->has_content() )
        {
            $link = $this->get_decoded_view_link();
            $tableWithinForm->table->addButton( $this->decoded_view_link_text, "submitbutton", "", false,
                "openNewWindow('$link');return false;" );

            $link = $this->get_download_view_link();
            $tableWithinForm->table->addButton( $this->get_download_link_text(), "submitbutton", "", false,
                "openNewWindow('$link');return false;" );
        }
        $this->view->inline_javascript[] = $tableWithinForm->get_javascript();

        $this->certs_details = new DataForm( "", "", "certs_form");
        $this->certs_details->removeDefaultSubmitButton();

        $certs_fieldset = $this->certs_details->createFieldset("lbl.FUSION_CERTDISPLAY_FIELDSET");
        $certs_label = new Label(tt_gettext("lbl.FUSION_CERTS_DESCRIPTION"));
        $certs_fieldset->addWidget($certs_label);
        $certs_fieldset->addWidget($tableWithinForm);

        //---------------------------------------------------------------------
    }


    protected function build_certificate_details()
    {
        if (isset($this->cert_objects))
        {
            $raised_key_warning = false;
            $raised_expired_warning = false;

            $i = 0;
            foreach ($this->cert_objects as $object)
            {
                $issuer = $this->blank;
                $subject = $this->blank;
                $issuer_without_ou = '';
                $type = $object->getFileType();
                $fingerprint = $object->get_fingerprint();

                if ($object->isCertificate())
                {
                    $is_ca = $object->is_ca();

                    $subject = $object->get_prettified_subject();
                    if ($subject == '')
                    {
                        $subject = $this->blank;
                    }

                    $issuer = $object->get_prettified_issuer(true);
                    $issuer_without_ou = $object->get_prettified_issuer(false);
                    if ($issuer == '')
                    {
                        $issuer = $this->blank;
                    }
                    if ($issuer_without_ou == '')
                    {
                        $issuer_without_ou = $this->blank;
                    }
                }
                else if ($object->isCRL())
                {
                    $issuer = $object->get_issuer();
                }
                else if ($object->isPrivateKey())
                {
                    if ($raised_key_warning == false)
                    {
                        $this->addError($this->ErrorFactory->get("CA_CERTIFICATE_KEY_PRESENT"));
                        $raised_key_warning = true;
                    }
                }

                if ($issuer_without_ou != $this->blank &&
                    $subject != $this->blank &&
                    $issuer_without_ou == $subject)
                {
                    $subject = tt_gettext("lbl.SUBJECT_MATCHES_ISSUER");
                }

                $expiry_date = $object->expiration_date();
                $this->obtainTimeZone();
                $expiry_date->setTimeZone(new DateTimeZone($this->time_display_zone));
                $expires = $expiry_date->format($this->time_display_format);

                // Figure out what to put in validity column
                // Deliberately using "if" and not "else if" so that
                // there is a priority order - e.g. it's more important
                // to indicate that a certificate has expired than it
                // not being a CA
                //
                // Valid
                // Not a CA
                // Not started
                // Expired
                // Invalid
                $validity = tt_gettext("lbl.VALID");
                if ($object->isCertificate() && $is_ca == false)
                {
                    $validity = tt_gettext("lbl.NOT_A_CA");
                }
                if (!$object->isPrivateKey() && $object->has_started() === false)
                {
                    $validity = tt_gettext("lbl.NOT_STARTED");
                }
                if (!$object->isPrivateKey() && $object->has_expired() === true)
                {
                    $validity = tt_gettext("lbl.EXPIRED");
                }
                if ($object->is_valid() === false)
                {
                    $validity = tt_gettext("lbl.INVALID");
                }

                if ($object->isCertificate() || $object->isCRL())
                {
                    if ($fingerprint == '')
                    {
                        // Failed to parse certificate/CRL so can't generate a fingerprint
                        $fingerprint = 0;
                        $hyperlink = false;
                    }
                    else
                    {
                        $link = "viewfusioncert?cert=" . $this->ca_file->get_alias() . "&fingerprint=" . base64_encode($fingerprint);
                        $hyperlink = new TextWithHyperlinks("", tt_gettext("link.VIEW"), $link, "", true);
                    }

                    $columns =  array_combine(  array("type", "issuer", "subject", "expires", "validity","view"),
                                                array($type, $issuer, $subject, $expires, $validity, $hyperlink));
                    $this->table_rows[] = array_merge( $columns, array('fingerprint' => $fingerprint,
                                                                       'link' => true,
                                                                       'uuid' => (string)$i));
                }
                else if ($object->isPrivateKey())
                {
                    $columns = array_combine(  array("type", "issuer", "subject", "expires", "validity","view"),
                                               array($type, $issuer, $subject, $expires, $validity, false));
                    $this->table_rows[] = array_merge( $columns, array('fingerprint' => $fingerprint,
                                                                       'link' => true,
                                                                       'uuid' => (string)$id));
                }
                else
                {
                    $this->table_rows[] = array_merge( $columns, array('fingerprint' => 0,
                                                                       'link' => false,
                                                                       'uuid' => (string)$i));
                }
                $i++;
            }
        }
        else
        {
            TTLOG_ERROR(getDeveloperLogger(), "No trusted CA list loaded");
        }
    }

    private function add_certs()
    {
        $post = json_encode("true");
        $this->rest_data_adapter->put_array(array("value" => $post),
            "configuration/cafe/cafestaticconfiguration/name/c_mgmt_certs_addFusionCertsToCA");

        // add support for VCS-E
        if($this->IProduct->isExpresswayEnabled())
        {
            touch("/tmp/request/addfusioncerts");
        }
    }

    private function remove_certs()
    {
        $post = json_encode("false");
        $this->rest_data_adapter->put_array(array("value" => $post),
            "configuration/cafe/cafestaticconfiguration/name/c_mgmt_certs_addFusionCertsToCA");

        // add support for VCS-E
        if($this->IProduct->isExpresswayEnabled())
        {
            touch("/tmp/request/removefusioncerts");
        }
    }

    private function poll_on_cert_removed($timeout, $removing=true)
    {
        $attempts = 0;
        while($attempts < $timeout)
        {
            if(FusionLib::are_fusion_certs_installed() === !$removing)
            {
                return true;
            }
            sleep(1);
            $attempts++;
        }
        return false;
    }

    private function updateData()
    {
        if(isset($_POST['submitbutton']))
        {
            if ( $_POST['submitbutton'] == tt_gettext($this->get_download_link_text()))
            {
                redirect($this->get_download_view_link());
            }
            else if ( $_POST['submitbutton'] == tt_gettext($this->decoded_view_link_text))
            {
                redirect($this->get_decoded_view_link());
            }

            else
            {
                if(FusionLib::are_fusion_certs_installed())
                {
                    // remove
                    $this->remove_certs();
                    if($this->poll_on_cert_removed(30))
                    {
                        $this->addError(new InfoMessage(tt_gettext("err.SUCCESS_SHORT_TITLE"), tt_gettext("err.REMOVED_FUSION_CERTS")));
                        success_redirect();
                    }
                    else
                    {
                        $this->addError(new InfoMessage(tt_gettext("err.ERROR_TITLE"), tt_gettext("err.TIMED_OUT_REMOVING_FUSION_CERTS")));
                        redirect();
                    }
                }
                else
                {
                    // add
                    $this->add_certs();
                    if($this->poll_on_cert_removed(30, false))
                    {
                        $this->addError(new InfoMessage(tt_gettext("err.SUCCESS_SHORT_TITLE"), tt_gettext("err.ADD_FUSION_CERTS")));
                        success_redirect();
                    }
                    else
                    {
                        $this->addError(new InfoMessage(tt_gettext("err.ERROR_TITLE"), tt_gettext("err.TIMED_OUT_ADDING_FUSION_CERTS")));
                        redirect();
                    }
                }
            }
        }
    }

    function writeContent()
    {
        if($this->form)
        {
            $this->form->render();
        }

        if(!$this->IProduct->isExpresswayEnabled())
        {
            if(FusionLib::are_fusion_certs_installed())
            {
                 $this->certs_details->render();
            }
            $xref = new CrossReferencePanel("RELATED TASKS");
            $target_type =  FusionLib::get_target_type($this->rest_data_adapter);
            if($target_type != "c_mgmt")
            {
                $xref->addEntry( "btn.REDIRECT_TO_CLOUD", "cloudregistration" );
            }
            else
            {
                $xref->addEntry( "btn.REDIRECT_TO_FUSION", "fusionregistration" );
            }
            $xref->addEntry( "Additional Certificate Management", "trustedcacertificate" );
            $xref->render();
        }
    }
}

$page = new FusionCertPage();
$page->render();

?>
