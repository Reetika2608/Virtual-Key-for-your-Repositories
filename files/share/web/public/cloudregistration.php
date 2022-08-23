<?php
require_once getenv("PHP_LIBDIR") . "/applicationpage.php";
require_once getenv("PHP_LIBDIR") . "/fusionstatustable.php";
require_once getenv("PHP_LIBDIR") . "/restcommand.php";
require_once getenv("PHP_LIBDIR") . "/cafejsonbloblib.php";
require_once getenv("PHP_LIBDIR") . "/datatablewrapper.php";
require_once getenv("PHP_LIBDIR") . "/alarmrenderer.php";

require_once getenv("PHP_LIBDIR") . "/fusionlib.php";
require_once getenv("PHP_LIBDIR") . "/management_lib.php";

// mimics urlsafe base64 encoding as used by ruby/java
// note, despite its name it still requries urlencoding because of = padding.
function base64_url_encode($input)
{
    return strtr(base64_encode($input), '+/', '-_');
}

class CloudRegistrationPage extends ApplicationPage
{
    private $info_form;
    private $services_ajax_table;
    private $service_form;
    private $service_details;
    private $rollback_form;
    private $rollforward_form;

    private $decoded_json_conf;
    private $registered = false;

    private $registration_form_container;
    private $run_precheck = true;

    const SESSION_ID_PREFIX = "temp_idp_session_id";
    const SECRET_INDEX = "temp_idp_secret";
    const IV_INDEX = "temp_iv_secret";
    const WAIT_TIME_FOR_CERTS_TO_BE_ADDED = 3;

    // This would be better taken from the manifest
    private $help_doc_map = array("c_cal" => "hybrid-services-calendar");

    function generate_safe_key($key_length=30)
    {   
        return base64_encode(openssl_random_pseudo_bytes($key_length));
    }

    // use rsa to encrypt keys.
    function publicly_encrypt_keys($json_blob, $public_key)
    {
        openssl_public_encrypt($json_blob, $crypted, $public_key);
        return base64_url_encode($crypted);
    }

    // decrypt aes encrypted returned data
    function decrypt_get_var($get_var, $shared_key, $iv)
    {
        $get_var = urldecode($get_var);

        // openssl module takes base64 encoded form, but we must swap out url base64 chars first
        $get_var = strtr($get_var, '-_', '+/');
        return openssl_decrypt($get_var, 'aes-256-cbc', base64_decode($shared_key), 0, base64_decode($iv));
    }

    // encrypt state blob with aes
    function encrypt_state_var($status, $shared_key, $iv)
    {
        // openssl_encrypt takes decoded keys and with OPENSSL_RAW_DATA returns raw bytes.
        $encrypted = openssl_encrypt(
            $status,
            'aes-256-cbc',
            base64_decode($shared_key),
            OPENSSL_RAW_DATA,
            base64_decode($iv)
        );
        // we want the encrypted data to be encoded with the java compatible base64_url_encode
        return base64_url_encode($encrypted);
    }

    function read_json_config_file()
    {
        $json_conf_location = "/opt/c_mgmt/etc/config/c_mgmt.json";
        if(!file_exists($json_conf_location)) {
            // if the response is not a file_location it is an error!
            $error = new ErrorMessage(tt_gettext("err.WARNING_TITLE"), $json_conf_location);
            $error->renderAsPage();
            die();
        }

        $json_conf = file_get_contents($json_conf_location);
        return json_decode($json_conf);
    }
    function generate_idp_link($return_link, $box_name, $session_id, $key, $iv, $action, $reregister=false)
    {
        // we don't use system_api for this as its web only info
        $public_key_location = "/opt/c_mgmt/etc/hercules.pem";
        if(file_exists($public_key_location)) {
            $public_key = file_get_contents($public_key_location);
        }
        else
        {
            return false;
        }

        $client_id = "C0cd283dc5b7d8bd5929a825324c74b4d2755d14cf52eb4b256f9a63bec15fce8";

        $idp_host = $this->decoded_json_conf->oauth->idpHost;
        $atlas_url_prefix = $this->decoded_json_conf->oauth->atlasUrlPrefix;
        $client_id = $this->decoded_json_conf->oauth->clientId;
        $cluster_id = $this->decoded_json_conf->system->clusterId;
        $reregisterstring = $reregister ? "true" : "false";

        // If this is a reregister then the orgId to use in the registration flow is the one from the machine account.
        // If this is a first time fuse we use the tempTargetOrgId from bootstrap - in that case we can't get to this
        // code unless the bootstrap data has been written to CDB
        if ($reregister) {
            $org_id = $this->decoded_json_conf->oauthMachineAccountDetails->organization_id;
            $reregisterstring = $reregisterstring . '", "org_id" : "' . $org_id;
        }
        else
        {
            $org_id = $this->decoded_json_conf->system->tempTargetOrgId;
        }

        $serial_number = $this->decoded_json_conf->system->serialNumber;
        $platform_version = $this->decoded_json_conf->system->version;
        //Connector Type append based on TargetType
        $target_type = $this->decoded_json_conf->system->targetType;
        $connector_id = $target_type."@".$serial_number;

        $version = "";
        $packages = $this->rest_data_adapter->get_local("status/tlp");

        if(isset($packages)) {
            for ($i = 0; $i < (int)$packages->num_recs; $i++)
            {
                $name = (string) $packages->record[$i]->package_name;
                if($name == "c_mgmt") {
                    $version  = (string) $packages->record[$i]->package_version;
                    break;
                }
            }
        }

        $encryption_blob = '{"session_id": "'. $session_id .'", "cipher_key": "'. $key .'", "cipher_iv": "'. $iv .'"}';
        $status_blob = '{"redirect_uri": "' . $return_link . '", '
                         . '"display_name": "' . $box_name . '", '
                         . '"connector_id": "' . $connector_id . '", '
                         . '"connector_type" : "' . $target_type . '", '
                         . '"reregistration" : "' . $reregisterstring . '", '
                         . '"cluster_id" : "' . $cluster_id . '", '
                         . '"org_id" : "' . $org_id . '", '
                         . '"serial" : "' . $serial_number . '", '
                         . '"version": "' . $version . '", '
                         . '"platform": "' . 'expressway' . '", '
                         . '"platform_version": "' . $platform_version . '", '
                         . '"protocol_version": "' . '3' . '" }';

        $encrypted_encryption_blob = $this->publicly_encrypt_keys($encryption_blob, $public_key);
        
        $encrypted_redirect_blob = $this->encrypt_state_var($status_blob, $key, $iv);

        $state = urlencode($encrypted_encryption_blob . "~" . $encrypted_redirect_blob);

        $link = $idp_host . "/idb/oauth2/v1/authorize"
         . "?response_type=token"
         . "&client_id=$client_id"
         . "&redirect_uri=" . urlencode($atlas_url_prefix) . "%2F" . $action . "_redirect"
         . "&scope=Identity%3ASCIM%20Identity%3AOrganization%20squared-fusion-mgmt%3Amanagement%20spark%3Alogs_write"
         . "&state=$state";

        return $link;
    }

    protected function init()
    {
        $target_type =  FusionLib::get_target_type($this->rest_data_adapter);
        // read json config file once at start
        $this->decoded_json_conf = ManagementLib::read_json_config_file();
        $this->updateData();
        $this->registered = FusionLib::is_registered($this->rest_data_adapter);
        if($this->is_unsupported_version() ) {
             $error_text = new TextWithHyperLinks(
                 "",
                 tt_gettext("err.UNSUPPORTED_PRODUCT_VERSION_TEXT_%s"),
                 array(tt_gettext("link.PRODUCT_DOWNLOAD") => tt_gettext("link.PRODUCT_DOWNLOAD_SOURCE"))
            );

            $this->addError(new InfoMessage(tt_gettext("err.UNSUPPORTED_PRODUCT_VERSION_%s"), $error_text));
        }

        if($this->is_penultimate_supported_version() ) {
            $error_text = new TextWithHyperLinks(
                "",
                tt_gettext("err.PENULTIMATE_SUPPORTED_PRODUCT_VERSION_TEXT_%s"),
                array(tt_gettext("link.PRODUCT_DOWNLOAD") => tt_gettext("link.PRODUCT_DOWNLOAD_SOURCE"))
            );

            $this->addError(new InfoMessage(tt_gettext("err.PENULTIMATE_SUPPORTED_PRODUCT_VERSION_%s"), $error_text));
        }

        if(!$this->registered) {
            $defusing = FusionLib::get_defused_state($this->rest_data_adapter) == "defusing";

            if(isset($_GET['remotedefuse']) ) {
                $this->addError(new InfoMessage(tt_gettext("err.REMOTE_DEFUSE_TITLE"), tt_gettext("err.REMOTE_DEFUSE")));
            }

            if(isset($_GET['defused']) || isset($_GET['remotedefuse']) || $defusing) {
                $this->run_precheck = false;
            }
            $this->initRegistrationForm();
        }
        else
        {
            if($this->is_cloud_maintenance_mode_set() ) {
                $this->addError(new InfoMessage(tt_gettext("err.CLOUD_MAINTENANCE_MODE_TITLE"), tt_gettext("err.CLOUD_MAINTENANCE_MODE")));
            }
            if(isset($_GET['uuid'])) {
                $service = $_GET['uuid'];
                $found_service = false;
                $entitled_services = $this->rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_entitledServices");
                if(isset($entitled_services->record[0])) {
                    $record = $entitled_services->record[0];
                    $decoded = json_decode($record->value);

                    if($decoded) {
                        foreach($decoded as $service_struct)
                        {
                            if(is_string($service_struct->name) && $service_struct->name == $service) {
                                $this->initServiceForm($service, $service_struct->display_name);
                                $found_service = true;
                                break;
                            }
                        }
                    }
                }
                if(!$found_service) {
                    redirect();
                }
            }
            else
            {
                $this->initServicesTable();
            }
        }
    }

    private function initServiceForm($service, $display_name)
    {

        // service form shows status and allows enabling / disabling
        $this->service_form = new DataForm($_SERVER['REQUEST_URI'], "wait_for_spinner", "dataform", "");

        $service_fieldset = $this->service_form->createFieldset($display_name);
        $status = new StatusWidget(tt_gettext("lbl.ERROR_READING_STATUS "), "error");

        // get status from FusionStatus
        $connector_status = FusionStatus::get_service_status_blob();
        $version = "";
        if(isset($connector_status->{$service})) {
            $status_node = $connector_status->{$service};
            if(isset($status_node->alarms) ) {
                $alarm_number = (int)$status_node->alarms;
            }
            $status = FusionStatus::create_status_label($status_node, $alarm_number);
            if($status_node->version != "None") {
                $version = $status_node->version;
            }
        }

        // for any spinners.
        $enabling_text = tt_escape_quotes_for_js(tt_gettext("msg.ENABLING_CONNECTOR"));

        // Get connector configured status from CDB
        $not_configured = FusionLib::is_not_configured($this->rest_data_adapter, $service);

        $service_widget = is_string($status) ? new Label($status) : $status;
        // if the connector configured status is not not_configured display the restart button
        if($status == tt_gettext("lbl.CONNECTOR_STOPPED") && !$not_configured) {
            $this->view->inline_style[] = ".has_button { padding-right:10px; }";
            //$service_widget->addCss
            $container = new Container("");
            $container->addWidget($service_widget);
            $restart_button = $this->service_form->getRenderableSubmitButton(
                "btn.RESTART_CONNECTOR", "trigger_loader_gif( '$enabling_text' );return true;", "restart_connector"
            );
            $service_widget->addCSSclass("has_button");
            $container->addWidget($restart_button);
            $service_widget = $container;
        }
        $service_fieldset->addRow("Status", $service_widget);

        // draw enabled dropdown if not c_mgmt
        if($service != "c_mgmt") {
            $enabled = FusionStatus::get_service_enabled($this->rest_data_adapter, $service) ? "true" : "false";

            // Needs to be double negative as it's looking for an explicit False case
            if (!$not_configured ) {
                $dropdown = new DropDownBox("enable_service", $enabled, tt_gettext("doc.FUSION_ENABLE_SERVICE"));
            }
            else
            {
                $dropdown = new DropDownBox("enable_service", $enabled, tt_gettext("doc.FUSION_CONFIGURE_SERVICE"));
                $dropdown->disable();
                $this->service_form->removeDefaultSubmitButton();
            }


            $dropdown->setValues(array("true" => tt_gettext("lbl.ENABLED"), "false" => tt_gettext("lbl.DISABLED")));
            $service_fieldset->addRow("Active", $dropdown, "enable_service_row");

            $this->service_form->addHiddenElement("old_value", $enabled);

            $spinner_js = <<<JS
            function wait_for_spinner(form)
            {
                if(document.getElementById('old_value').textContent == "false" && document.getElementById('enable_service').textContent == "true" )
                {
                    trigger_loader_gif( "$enabling_text" );
                }
                return valuespace_validation(form);
            }
JS;
            $this->view->inline_javascript[] = $spinner_js;
        }
        else
        {
            // disable form if c_mgmt. Cannot deactivate managementconnector without defusing.
            $this->service_form->removeDefaultSubmitButton();
        }

        // add config links if available
        $config_pages = FusionStatus::get_related_tasks($service, true);
        if($config_pages) {
            //style for seperating links in a container
            $this->view->inline_style[] = ".additional_link { padding-left:10px; }";
            foreach ($config_pages as $config_page_details)
            {
                $url = $config_page_details->location;
                if(isset($config_page_details->configure_token)) {
                    $token = $config_page_details->configure_token;
                }
                else if(isset($config_page_details->status_token)) {
                    $token = $config_page_details->status_token;
                }
                $label = "";
                $widget = "";
                $status_widget = false;
                
                if(isset($config_page_details->label)) {
                    $label = $config_page_details->label;   
                }

                // for lists of config we can display the number of listed items (and if that meets minimum requirement)
                if(isset($config_page_details->cdb_count)) {
                    $widget = new Container("");

                    $cdb_path = $config_page_details->cdb_count;
                    $count = count(BlobLibrary::get_list($this->rest_data_adapter, $cdb_path));
                    $widget->addWidget(new Label($count));

                    $link = new Hyperlink("", tt_gettext($token), $url);
                    $link->addCSSclass("additional_link");

                    $widget->addWidget($link);

                    // figure out count and display
                    if(isset($config_page_details->minimum_count) 
                        && $count < $config_page_details->minimum_count // minimumcount
                    ) {
                        $status_widget = new Label(tt_gettext($config_page_details->minimum_count_label));
                    }
                }
                else
                {
                    $widget = new Hyperlink("", tt_gettext($token), $url);
                }
                $service_fieldset->addRow($label, $widget, "", $status_widget);
            }
        }


        $this->service_form->addSubmitButton("btn.REDIRECT_TO_CLOUD", "location.href='cloudregistration';return false;");
        $this->view->inline_javascript[] = $this->service_form->get_valuespace_javascript("valuespace_validation");

        $blocked_version = ManagementLib::get_blocked_versions($service, $this->rest_data_adapter);
        $rollback_version = ManagementLib::get_rollback_details($service);
        $blocked_rollback_version = ManagementLib::get_blocked_rollback_details($service, $this->rest_data_adapter);

        if($blocked_version && ManagementLib::is_app_version_different($blocked_version, $version)) {
            $this->view->inline_javascript[] = ManagementLib::get_rollback_confirmation_js("ROLLFORWARD");
            $this->rollforward_form = new DataForm("", "", "rollforward_form");
            $this->rollforward_form->removeDefaultSubmitButton();
            $form = $this->rollforward_form;
            $confirmRollbackJs = 'return confirm_rollback(form);';
            $rollforward_fieldset = $this->rollforward_form->createFieldset("fieldset.ROLLFORWARD");
            $rollforward_fieldset->addRow("lbl.BLOCKED_ROLLFORWARD_VERSION", new Label($blocked_version));
            $this->rollforward_form->addSubmitButton("btn.ROLLFORWARD", $confirmRollbackJs, "rollforward");
        }
        if($rollback_version && !($blocked_rollback_version && $blocked_rollback_version == $rollback_version)) {
            $this->view->inline_javascript[] = ManagementLib::get_rollback_confirmation_js("ROLLBACK");
            $this->rollback_form = new DataForm("", "", "rollback_form");
            $this->rollback_form->removeDefaultSubmitButton();
            $form = $this->rollback_form;
            $confirmRollbackJs = 'return confirm_rollback(form);';
            $rollback_fieldset = $this->rollback_form->createFieldset("fieldset.ROLLBACK");
            $rollback_fieldset->addRow(
                "lbl.ROLLBACK_VERSION", new Label($rollback_version), "",
                new StatusWidget(sprintf(tt_gettext("lbl.ROLLBACK_WARNING_%s"), $version), "warning")
            );
            $this->rollback_form->addSubmitButton("btn.ROLLBACK", $confirmRollbackJs, "rollback");
        }


        // create empty form for config links and alarms
        $this->service_details = new DataForm("", "", "details_form");
        $this->service_details->removeDefaultSubmitButton();



        // add alarms if any
        $alarms = ManagementLib::get_alarms_for_service($service, $this->rest_data_adapter);
        if(!empty($alarms)) {
            $alarms_fieldset = $this->service_details->createFieldset("ttl.ALARMS");

            $table_data = array();
            $my_addresses = $this->IProduct->getIPAddrList();
            $my_addresses[] = "127.0.0.1";

            // reformat data
            foreach($alarms as $alarm)
            {
                $table_row = array_combine(
                    array("alarm", "description", "status", "severity",
                                                        "peer", "action", "first_raised", "last_raised", "id", "has_check"),
                    create_alarm_row(
                        $alarm, $my_addresses,
                        $this->IProduct, $this->currentLanguageCode
                    )
                );
                $table_row['uuid'] = (string)$alarm->id;
                $table_data[] = $table_row;
            }

            $header_xpaths = array(
                "Alarm" => "alarm",
                "Description" => "description",
                "State" => "status",
                "Severity" => "severity",
                "Action" => "action",
                "ID" => "id" );

            // Store the table as a property so we can exec its writeJavascript() method.
            $tableWithinForm = new DataTableWrapper($header_xpaths);
            $tableWithinForm->set_listing_only(true);
            $tableWithinForm->suppressDefaultActions();
            $tableWithinForm->isTextLinkEnabled(false);

            $tableWithinForm->initialise(count($table_data));
            $tableWithinForm->add_rows($table_data);
            $tableWithinForm->suppressFormTags();

            $tableWithinForm->table->addFooterElement(new Hyperlink("", tt_gettext("link.ACKNOWLEDGE_ALARMS"), "alarms"));
            $this->view->inline_javascript[] = $tableWithinForm->get_javascript();
            $alarms_fieldset->addWidget($tableWithinForm);
        }
    }

    private function remove_blocked_versions($service)
    {
        $root = $this->rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_installed_blacklist");
        if(isset($root->record[0])) {
            $record = $root->record[0];
            $decoded = json_decode($record->value);
            if($decoded && isset($decoded->{$service}) ) {
                unset($decoded->{$service});
                $post = json_encode($decoded);
                $this->rest_data_adapter->put_array(
                    array("value" => $post),
                    "configuration/cafe/cafeblobconfiguration/name/c_mgmt_installed_blacklist"
                );
                return true;
            }
        }
        return false;
    }

    private function get_alarm_range($service)
    {
        $start = 0;
        $end = 0;

        $path = "/mnt/harddisk/current/fusion/manifest/$service.json";
        if (file_exists($path)) {
            $json = file_get_contents($path);
            $decoded = json_decode($json);
            if($decoded) {
                if(isset($decoded->alarms)) {
                    $start = (int)$decoded->alarms->start;
                    $end = (int)$decoded->alarms->end;
                }
            }
        }
        // lookup file, extract alarm range
        return array($start, $end);
    }

    private function get_alarms_for_service($service)
    {
        list($start, $end) = $this->get_alarm_range($service);
        $alarm_root = $this->rest_data_adapter->get("/status/alarm");
        $alarms = array();
        foreach($alarm_root->record as $record)
        {
            if($record->id >= $start && $record->id <= $end && (string)$record->status != "lowered") {
                $alarms[(string)$record->id] = $record;
            }
        }
        return $alarms;
    }

    private function revive_required()
    {
        $root = $this->rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_reRegisterRequired");
        return (int)$root->num_recs > 0 && $root->record[0]->value == '"true"';
    }

    /*
    * If registered we're going to create an information form fieldset and a table of the services.
    */
    private function initServicesTable()
    {

        // info_form is a fieldset of info sitting above the services table  
        $this->info_form = new DataForm("", "", "fused_form");
        // form has no submit function 
        $this->info_form->removeDefaultSubmitButton();
        $fieldset = $this->info_form->createFieldset("fieldset.CLOUD_SERVICES_REGISTERED");
        $registered_message = sprintf(tt_gettext("lbl.FUSION_REGISTERED"), FusionLib::get_target_service($this->rest_data_adapter, $this->IProduct->isExpresswayEnabled()));
        $fieldset->addRow("", new Text($registered_message));

        if(FusionLib::are_fusion_certs_installed()) {
            // use certs link
            $cert_text = "lbl.FUSION_CERTS_ARE_ACCEPTED_%s";
        }
        else
        {
            // refuse certs link
            $cert_text = "lbl.FUSION_CERTS_ARE_NOT_ACCEPTED_%s";
        }

        $cert_link = new TextWithHyperLinks(
            "", tt_gettext($cert_text), 
            array(tt_gettext("ttl.FUSION_CERT_TOOL") => "fusioncerts")
        );

        $fieldset->addRow("", $cert_link);

        $cloud_services_text = tt_gettext("lbl.CLOUD_SERVICES_MESSAGE_%s");

        // get hyperlink link to atlas portal which will be somehting like: 
        // https://admin.projectsquared.com/?hercules-host=https://hercules-a.wbx2.com#/overview
        if($this->decoded_json_conf ) {
            $atlas_fusion_portal = $this->decoded_json_conf->oauth->atlasAdminFusionPortal;
        
            $cloud_services_label = new TextWithHyperLinks(
                "", $cloud_services_text,
                array(tt_gettext("link.CISCO_CLOUD_COLLABORATION_PORTAL") => $atlas_fusion_portal),
                "", true
            );
            $fieldset->addRow("", $cloud_services_label);

            // if flag is set provide revive button
            if($this->revive_required()) {
                $revive_button_container = new Container("");
                $revive_text = new StatusWidget(new Label(tt_gettext("lbl.FUSION_REVIVE_MAY_BE_REQUIRED")), 'error');
                $revice_button = $this->info_form->getRenderableSubmitButton("btn.FUSION_REVIVE", "", "revive");
                $revive_button_container->addWidget($revive_text);
                $revive_button_container->addWidget($revice_button);
                $fieldset->addRow("", $revive_button_container);
            }

            // if flag is set provide local defuse button
            if($this->is_node_being_removed()) {
                $txt_DEFUSE_CONFIRM = tt_escape_quotes_for_js(tt_gettext('msg.DEFUSE_CONFIRM'));

                $code = <<<EOT
                function confirm_defuse(f)
                {
                    defuseform= f;
                    return tt_confirm("$txt_DEFUSE_CONFIRM", "defuseform.submit()");
                }
EOT;
                $form = $this->info_form;
                $this->view->inline_javascript[] = $code;
                $confirmDefuseJs = 'return confirm_defuse(form);';
                $defuse_text_container = new Container("");
                $defuse_text = new StatusWidget(new Label(tt_gettext("lbl.DEFUSE_LOCAL")), 'error');
                $defuse_button = $this->info_form->getRenderableSubmitButton("btn.DEFUSE", $confirmDefuseJs, "defuse");
                $defuse_text_container->addWidget($defuse_text);
                $fieldset->addRow("", $defuse_text_container);
                $fieldset->addRow("", $defuse_button);
            }
        }

        $fieldset->hide_labels();

        $services_fieldset = $this->info_form->createFieldset("fieldset.CLOUD_SERVICES");

        // draw service table inside fieldset
        $status_label = new Label(tt_gettext("lbl.FUSION_STATUS_INSTRUCTIONS"));
        $services_fieldset->addWidget($status_label);
        $this->services_ajax_table = new FusionStatus($this->rest_data_adapter);
        $services_fieldset->addWidget($this->services_ajax_table);
        
        $this->view->inline_style[] = "form.tt_form { padding-bottom: 0px;}";

        $this->view->inline_javascript[] = $this->services_ajax_table->get_javascript();
        $this->view->inline_javascript[] = $this->get_fused_check_ajax();
    }

    private function get_fused_check_ajax()
    {
        $js = <<<JS

            setAjaxTimeout();

            function setAjaxTimeout()
            {
                setTimeout("sendAjaxRequest()", 5000);
            }

            function sendAjaxRequest()
            {   
                jQuery.ajax({
                  method: "GET",
                  url: "/fusionfusedajaxcheck",
                }).done(function( data ) {
                    handleAjaxResponse ( data );
                }).fail(function () {
                    // TODO
                });

            }

            function handleAjaxResponse( data )
            {
                if ( data == "defused")
                {
                    location.href = "/cloudregistration";
                }
                else if ( data == "defusing")
                {
                    location.href = "/cloudregistration?remotedefuse";   
                }
                else
                {
                    setAjaxTimeout();
                }
            }

JS;
        return $js;
    }

    private function is_root_password_default()
    {
        return $this->IProduct->check_alarm("40003") ||
            $this->IProduct->check_alarm("712ba24b-6725-42c2-87fc-f71552abe95e");
    }

    private function is_admin_password_default()
    {
        return $this->IProduct->check_alarm("40005") ||
            $this->IProduct->check_alarm("5ac18763-6d5d-46a3-bbaa-61ebb2f17c2f");
    }

    private function is_password_md5()
    {
        return $this->IProduct->check_alarm("40028") ||
            $this->IProduct->check_alarm("52b68d89-769b-4881-a3c4-d6d038f8cc7a");
    }

    private function is_ntp_broken()
    {
        return $this->IProduct->check_alarm("25002") ||
            $this->IProduct->check_alarm("992bace4-fac4-11de-91d1-00223ff026c1");
    }

    private function is_unsupported_version()
    {
        return $this->IProduct->check_alarm("60072") ||
            $this->IProduct->check_alarm("3e544328-598e-11e6-8b77-86f30ca893d3");
    }

    private function is_penultimate_supported_version()
    {
        return $this->IProduct->check_alarm("60073") ||
            $this->IProduct->check_alarm("38d69632-5fd8-4b44-94d7-a517b8329eb8");
    }

    private function is_cloud_maintenance_mode_set()
    {
        $target_type = $this->decoded_json_conf->system->targetType;
        if($target_type == "c_mgmt") {
            $HEARTBEAT = "/var/run/c_mgmt/c_mgmt.heartbeat";
        }
        else
        {
            $HEARTBEAT = "/var/run/c_ccucmgmt/c_ccucmgmt.heartbeat";
        }
        //$HEARTBEAT = "/var/run/c_ccucmgmt/c_ccucmgmt.heartbeat";
        $maintenanceMode = "off";

        if(file_exists($HEARTBEAT)) {
            $json_file = file_get_contents($HEARTBEAT);

            $jfo = json_decode($json_file);

            $maintenanceMode = $jfo->provisioning->maintenanceMode;
        }
        return $maintenanceMode == "on";
    }

    private function is_node_being_removed()
    {
        $decluster = false;
        if($this->is_cloud_maintenance_mode_set() ) {
            $cluster_serials = $this->decoded_json_conf->system->clusterSerials;
            $serial_number = $this->decoded_json_conf->system->serialNumber;

            if ((count($cluster_serials) == 1) && (in_array($serial_number, $cluster_serials))) {
                $decluster = true;
            }
        }
        return $decluster;
    }

    /*
    * If not registered we're going to create a registration_form.
    * This form will simply show a spinner till it is updated with ajax
    */

    private function check_basic_requirements()
    {
        if($this->is_admin_password_default() || $this->is_root_password_default() ) {
            // password reset error with link to alarm page
            $error_text = new TextWithHyperLinks(
                "",
                tt_gettext("err.PASSWORD_HAS_DEFAULT_VALUE_SEE_ALARMS_%s"),
                array(tt_gettext("link.ALARMS") => "alarms")
            );

            $this->addError(new ErrorMessage(tt_gettext("err.SECURITY_REQUIREMENTS_NOT_MET_FOR_FUSION"), $error_text));
        }
        else if($this->is_password_md5() ) {
            // md5 error with link to alarm page
            $error_text = new TextWithHyperLinks(
                "",
                tt_gettext("err.PASSWORD_HAS_MD5_ENCRYPTION_%s"),
                array(tt_gettext("link.ALARMS") => "alarms")
            );

            $this->addError(new ErrorMessage(tt_gettext("err.SECURITY_REQUIREMENTS_NOT_MET_FOR_FUSION"), $error_text));
        }
        else if($this->is_ntp_broken() ) {
            // md5 error with link to alarm page
            $error_text = new TextWithHyperLinks(
                "",
                tt_gettext("err.NTP_SETUP_BROKEN_%s"),
                array(tt_gettext("link.ALARMS") => "alarms")
            );

            $this->addError(new ErrorMessage(tt_gettext("err.NETWORK_REQUIREMENTS_NOT_MET_FOR_FUSION"), $error_text));
        }
        else if(!ManagementLib::is_hostname_and_domain_set($this->rest_data_adapter)) {
            // link to dns page to set 
            $error_text = new TextWithHyperLinks(
                "",
                tt_gettext("err.MISSING_HOSTNAME_OR_DOMAIN_%s"),
                array(tt_gettext("menu.DNS") => "dns")
            );

            $this->addError(new ErrorMessage(tt_gettext("err.DNS_REQUIREMENTS_NOT_MET_FOR_FUSION"), $error_text));

        }
        else
        {
            return true;
        }
        return false;
    }


    private function initRegistrationForm()
    {
        if(isset($_GET['signature']) && isset($_GET['bootstrap'])) {
            list($success, $error) = BlobLibrary::run_xcommand(
                $this->/etc/service_template::clean_up on exit." ,
                "c_mgmt", "verify_signature", $_GET['bootstrap'] . " " . $_GET['signature']
            );
            if(!$success ) {
                $this->addError(new ErrorMessage(tt_gettext("err.BOOTSTRAP_SIGNATURE_FAILURE"), tt_gettext("err.BOOTSTRAP_SIGNATURE_FAILURE_MESSAGE")));
            }
        }
        if ($this->check_basic_requirements()) {
            $this->view->inline_style[] = ".registration_indent { padding-left:30px; }";
            $this->view->inline_style[] = ".tickbox_additional_spacing { padding-left:10px; }";

            $this->registration_form_spinner($this->run_precheck);
        }
    }

    private function registration_form_spinner( $registration = true )
    {

        if ($registration ) {
            $message = new Label(tt_gettext("lbl.FUSION_REGISTRATION_POLLING"));
            $url = '/fusionregistrationajax.php';
        }
        else {
            $message = new Label(tt_gettext("lbl.FUSION_DEREGISTRATION_WAIT"));
            $url = '/fusionderegistrationajax.php';
        }

        $javascript = <<<EOT
            jQuery.ajax({
               url: "$url",
               type: "get",
               dataType: "html",
               success: function ( returnData ) {
                 jQuery("#registration_form_container").html(returnData);
               },
               error: function(e){
                 console.error ( e ) ;
               }
            });
EOT;

        $this->registration_form_container = new Container("registration_form_container");
        $this->view->on_DOM_ready_javascript[] = $javascript;

        // init registration form insinde container
        $registration_form = new DataForm($_SERVER['REQUEST_URI'], "", "registration_form", "");
        $this->registration_form_container->addWidget($registration_form);

        $registration_form->removeDefaultSubmitButton();
        $fieldset = $registration_form->createFieldset("fieldset.CLOUD_SERVICES");
        
        $fieldset->hide_labels();

        $spinner_container = new Container("");

        $spinner = new Image("/inc/images/misc/loader.gif", 32, 32, "Loading");
        // position spinner
        $spinner->addCSSclass("inline_spinner");
        $this->view->inline_style[] = ".inline_spinner { padding-right:10px; padding-bottom:10px; vertical-align: middle;}";

        $spinner_container->addWidget($spinner);
        $spinner_container->addWidget($message);

        $fieldset->addRow("", $spinner_container);
    }

    private function wait_for_service_start($service, $max_wait=10)
    {
        // wait for the service to start
        while($max_wait > 0)
        {
            if($this->is_service_running($service)) {
                return true;
            }
            $max_wait--;
            sleep(1);
        }
        return false;
    }

    private function is_service_running($service)
    {
        $connector_status = FusionStatus::get_service_status_blob();
        if(isset($connector_status->{$service})) {
            return (string)$connector_status->{$service}->composed_status === "running";
        }
        return false;
    }

    private function updateData()
    {
        if (isset($_POST['submitbutton']) && isset($_GET['uuid'])) {
            if($_POST['submitbutton'] == tt_gettext('btn.SAVE')) {
            
                // Handle enable / disabling from services table
                $mode = $_POST['enable_service'];
                $service = $_GET['uuid'];
                $new_states = array($service => $mode);    
                
                $root = $this->rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_enabledServicesState");
                if(isset($root->record[0])) {
                    $record = $root->record[0];
                    $decoded = json_decode($record->value);

                    if($decoded) {
                        foreach ($decoded as $name => $enabled)   
                        {
                            if(!array_key_exists($name, $new_states)) {
                                $new_states[$name] = $enabled;
                            }
                        }
                    }
                }
                
                $state_table = "c_mgmt_system_enabledServicesState";

                // Get the list append to it and push back
                $this->rest_data_adapter->put_array(
                    array("name" => $state_table,
                          "value" => json_encode($new_states)),
                    "configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_enabledServicesState"
                );

                if($mode === "true" && $_POST['old_value'] === "false") {
                    $this->wait_for_service_start($service);
                }
                else if($mode === "false" && $_POST['old_value'] === "true") {
                    // sleep to give service a fighting chance of updating its status in time.
                    sleep(1);
                }

                 $this->addError($this->ErrorFactory->get("saved"));
                 success_redirect();
            }
            else if ($_POST['submitbutton'] == tt_gettext('btn.RESTART_CONNECTOR')) {
                $service = $_GET['uuid'];
                list($success, $error) = BlobLibrary::run_xcommand(
                    $this->rest_data_adapter,
                    "c_mgmt", "control", $service . " restart"
                );
                if($success && $error == "$service restart Complete") {
                    $restart_success = $this->wait_for_service_start($service, 15);
                    if($restart_success) {
                        $this->addError(new InfoMessage(tt_gettext("err.SUCCESS_SHORT_TITLE"), tt_gettext("err.CONNECTOR_RESTARTED")));
                        success_redirect("cloudregistration");
                    }
                    else
                    {
                        $error = tt_gettext("err.CONNECTOR_RESTART_TIMED_OUT");
                    }
                }
                else
                {
                    $error = FusionLib::formatErrorParams($error);
                }
                $this->addError(new ErrorMessage(tt_gettext("Failed"), $error));
                redirect();
            }
            else if ($_POST['submitbutton'] == tt_gettext('btn.ROLLBACK')) {
                $service = $_GET['uuid'];
                if(ManagementLib::get_rollback_details($service)) {
                    list($success, $error) = BlobLibrary::run_xcommand($this->rest_data_adapter, "c_mgmt", "rollback", $service);
                    // sleep to give service a fighting chance of updating its status in time.
                    if($success) {
                        // can we see the rollback happening??
                        $this->addError(new InfoMessage(tt_gettext("err.SUCCESS_SHORT_TITLE"), tt_gettext("err.ROLLBACK_STARTED")));
                        success_redirect("cloudregistration");
                    }
                    else
                    {
                        $error = FusionLib::formatErrorParams($result->error);
                        $this->addError(new ErrorMessage(tt_gettext("Failed"), $error));
                    }
                }
                redirect();
            }
            else if ($_POST['submitbutton'] == tt_gettext('btn.ROLLFORWARD')) {
                $service = $_GET['uuid'];
                if($this->remove_blocked_versions($service, $this->rest_data_adapter)) {
                    $this->addError(new InfoMessage(tt_gettext("err.SUCCESS_SHORT_TITLE"), tt_gettext("err.ROLLFOWARD_ALLOWED")));
                    success_redirect("cloudregistration");
                }
                redirect();
            }
        }
        else if(isset($_POST['submitbutton'])) {
            if ($_POST['submitbutton'] == tt_gettext('btn.DEFUSE')) {
                // Defuse in progress
                $success = false;
                $error = "";
                list($success, $error) = BlobLibrary::run_xcommand($this->rest_data_adapter, "c_mgmt", "defuse", array());

                if($success) {
                    $this->addError(new InfoMessage(tt_gettext("err.SUCCESS_SHORT_TITLE"), tt_gettext("err.FUSION_DEFUSED")));
                    success_redirect("cloudregistration?defused");
                }
                else
                {
                    $this->addError(new InfoMessage(tt_gettext("Failed"), $error));
                    redirect("cloudregistration");
                }
            }
            else if ($_POST['submitbutton'] == tt_gettext('btn.BOOTSTRAP_FMC')) {
                $registered = FusionLib::is_registered($this->rest_data_adapter);

                if(!$registered) {
                    if (isset($_POST['use_fusion_ca'])) {
                        $post = json_encode("true");
                        $this->rest_data_adapter->put_array(
                            array("value" => $post),
                            "configuration/cafe/cafestaticconfiguration/name/c_mgmt_certs_addFusionCertsToCA"
                        );
                    }
                    else
                    {
                        $post = json_encode("false");
                        $this->rest_data_adapter->put_array(
                            array("value" => $post),
                            "configuration/cafe/cafestaticconfiguration/name/c_mgmt_certs_addFusionCertsToCA"
                        );
                    }
                }
                $prevent_upgrade_record = $this->rest_data_adapter->get_local("configuration/cafe/cafestaticconfiguration/name/c_mgmt_config_preventMgmtConnUpgrade");
                $prevent_upgrade = false;

                if (isset($prevent_upgrade_record) && (int)$prevent_upgrade_record->num_recs > 0) {
                    if ((string)$prevent_upgrade_record->record[0]->value === "on") {
                        $prevent_upgrade = true;
                    }
                }
                if (!$prevent_upgrade) {
                    sleep(self::WAIT_TIME_FOR_CERTS_TO_BE_ADDED);
                    $this->install_latest_c_mgmt();
                }
                redirect();
            }
            else
            {
                // run revive command
                $reregister =  $_POST['submitbutton'] == tt_gettext("btn.FUSION_REVIVE");

                $redirect = $_SERVER['SCRIPT_URI'];
                $fms_action = "fuse";

                $box_name = $this->IProduct->getSystemName();

                $domain_name = "";
                if($this->decoded_json_conf ) {
                    $domain_name = $this->decoded_json_conf->system->domainname;
                }

                if ($box_name != "" && $domain_name != "") {
                    $box_name = $box_name . '.' . $domain_name;
                }

                $session_id = $this->generate_safe_key();
                $shared_secret = $this->generate_safe_key(32);
                $shared_iv = $this->generate_safe_key(16);

                $_SESSION[self::SESSION_ID_PREFIX] = $session_id;
                $_SESSION[self::SECRET_INDEX] = $shared_secret;
                $_SESSION[self::IV_INDEX] = $shared_iv;

                $url = $this->generate_idp_link($redirect, $box_name, $session_id, $shared_secret, $shared_iv, $fms_action, $reregister);
                if($url) {
                    redirect($url);
                }
                else
                {
                    $this->addError(new ErrorMessage(tt_gettext("Failed"), tt_gettext("err.CAFE_REDIRECT_FAILING")));
                    redirect();
                }
            }
        }


        else if(isset($_GET['payload'])) {
            $success = false;
            $error = "";

            if(!isset($_SESSION[self::IV_INDEX]) || !isset($_SESSION[self::SECRET_INDEX]) || !isset($_SESSION[self::SESSION_ID_PREFIX])) {
                $success = false;
                $error = tt_gettext("err.REGISTRATION_SESSION_TIMED_OUT");
            }
            else
            {
                $iv = $_SESSION[self::IV_INDEX];
                $key = $_SESSION[self::SECRET_INDEX];
                $payload = json_decode($this->decrypt_get_var($_GET['payload'], $key, $iv), true);
                $session_id = $payload['sessionId'];

                if($session_id === $_SESSION[self::SESSION_ID_PREFIX]) {
                    //clear up
                    unset($_SESSION[self::SECRET_INDEX]);
                    unset($_SESSION[self::SESSION_ID_PREFIX]);
                    unset($_SESSION[self::IV_INDEX]);

                    $cluster_id = $payload['clusterId'];
                    $machine_account = json_encode($payload['machineAccount']);
                    $machine_account = str_replace(" ", "", $machine_account);

                    $xcommand_params = $cluster_id . " " . $machine_account;

                    $params["connector"] = "c_mgmt";
                    $params["parameters"] = $xcommand_params;
                    $params["connector_cmd"] = "init";
                    $registered = FusionLib::is_registered($this->rest_data_adapter);

                    if($registered) {
                        $params["parameters"] = $xcommand_params." reregister";
                    }

                    $command = new RestCommand($this->rest_data_adapter, "cafe", $params);

                    $result = $command->start();
                    $results = $result->results();

                    if ($result->error) {
                        $success = false;
                        $error = FusionLib::formatErrorParams($result->error);
                    } 
                    else if(isset($results[0]['info'])) {
                        $info = $results[0]['info'];
                        if(preg_match("/Success Full Startup*/", $info)) {
                            $success = true;
                        }
                    }
                }
                else
                {
                    $success = false;
                    $error = tt_gettext("err.REGISTRATION_SESSION_TIMED_OUT");
                }
            }

            if($success) {
                $this->addError(new InfoMessage(tt_gettext("err.SUCCESS_SHORT_TITLE"), tt_gettext("err.REGISTERED_FOR_FUSION")));
                success_redirect("cloudregistration");
            }
            else
            {
                $this->addError(new ErrorMessage(tt_gettext("lbl.FAILED"), $error));
                redirect("cloudregistration");
            }
        }
    }

    private function install_latest_c_mgmt()
    {
        if ($this->decoded_json_conf) {
            $latest_package_response = FusionLib::get_latest_package_info($this->decoded_json_conf);
            $json_latest_package = json_decode($latest_package_response);
            if (isset($json_latest_package)) {
                if (FusionLib::get_c_mgmt_version() != $json_latest_package->version) {
                    BlobLibrary::run_xcommand(
                        $this->rest_data_adapter, "c_mgmt", "prefuse_install",
                        $json_latest_package->tlpUrl . " " . $json_latest_package->version
                    );

                    $install_completed = $this->poll_on_package_install($json_latest_package->version, 60);
                    if (!$install_completed ) {
                        $this->addError(new ErrorMessage(tt_gettext("Failed"), tt_gettext("err.BOOTSTRAP_INSTALL_TIMEOUT")));
                    }
                }
            }
            else
            {
                $this->addError(new ErrorMessage(tt_gettext("Failed"), $latest_package_response));
            }
        }
    }

    private function poll_on_package_install($version, $timeout)
    {
        $attempts = 0;
        while($attempts < $timeout)
        {
            $installed_version = FusionLib::get_c_mgmt_version();

            if($version === $installed_version) {
                return true;
            }

            sleep(1);
            $attempts++;
        }
        return false;
    }

    private function get_help_doc_id()
    {
        if(isset($_GET['uuid']) && array_key_exists($_GET['uuid'], $this->help_doc_map)) {
            return $this->help_doc_map[$_GET['uuid']];
        }
        return "hybrid-services";
    }

    public function get_page_title_for_help()
    {
        return "cloudregistration";
    }

    public function set_help_js()
    {
        if(!$this->registered) {
            return parent::set_help_js();
        }
        else
        {
            return FusionLib::get_knowledge_base_js($this->get_help_doc_id());
        }
    }

    public function set_help_path()
    {
        if(!$this->registered) {
            return parent::set_help_path();
        }
        else
        {
            return FusionLib::get_knowledge_base_url($this->get_help_doc_id());
        }
    }

    public function writeContent()
    {

        if($this->registration_form_container) {
            $this->registration_form_container->render();
        }

        // if registered we'll have an info form and services table, we should also add some related tasks

        if(isset($_GET['uuid'])) {
            if($this->service_form) {
                $this->service_form->render();
            }
            if($this->rollback_form) {
                $this->rollback_form->render();
            }
            if($this->rollforward_form) {
                $this->rollforward_form->render();
            }
            if($this->service_details) {
                $this->service_details->render();
            }
        }
        else
        {
            if($this->info_form) {
                $this->info_form->render();
            }
            if ($this->registered) {
                $files = glob("/mnt/harddisk/current/fusion/related_tasks/*.json");
                if(!empty($files)) {
                    $xref = new CrossReferencePanel("RELATED TASKS");
                    $xref->add_top_margin(50);
                    foreach ($files as $file_path) {
                        try {
                            $link_json = file_get_contents($file_path);
                            $decoded = json_decode($link_json);
                            if($decoded) {
                                foreach($decoded as $token => $link)
                                {
                                    // make sure file exists.
                                    if (preg_match('/^(\w+)/', $link, $m)) {
                                        $php_link = $m[1] . ".php";
                                        if (file_exists($php_link)) {
                                            $xref->addEntry($token, $link); 
                                        }
                                    }
                                }
                            }
                        } catch (Exception $e) {
                            // couldn't open or decode file, move on.
                        }
                    }
                    $xref->render();
                }
            }
        }
    }
}

$page = new CloudRegistrationPage();
$page->render();
