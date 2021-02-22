<?php

require_once( getenv("PHP_LIBDIR") . "/widgets/textwithhyperlinks.php");

class FusionLib
{
    static public function get_knowledge_base_url($alias)
    {
        return "https://www.cisco.com/go/" . $alias;
    }

    static public function get_knowledge_base_js($alias)
    {
        return "openNewWindow('". self::get_knowledge_base_url($alias) ."'); return false";
    }

    // checks to see if we're using the provided fusionc erts
    static public function are_fusion_certs_installed()
    {
        $FUSION_DIR_PATH = "/tandberg/persistent/certs/fusionadded/";
        // we can check tell if fusion certs are installed by checking if the following dir exists:
        return file_exists($FUSION_DIR_PATH) && is_dir($FUSION_DIR_PATH);
    }

    // get the current status for tracking_id
    static public function get_log_status($tracking_id)
    {
        $LOG_TRACK = "/mnt/harddisk/persistent/fusion/log/log_id.json";

        $rtn = false;

        if(file_exists($LOG_TRACK))
        {
            $json_file = file_get_contents($LOG_TRACK);

            $jfo = json_decode($json_file);
            if (json_last_error() === JSON_ERROR_NONE)
            {
                $log_id = $jfo->logsearchId;
                $status = $jfo->status;

                if($log_id == $tracking_id)
                {
                    $rtn = $status;

                    if ($status === "error")
                    {
                        $cause = $status;
                        if (isset($jfo->cause))
                        {
                            $cause = $jfo->cause;
                        }

                        switch ($cause)
                        {
                            case "managed-certs":
                                $rtn = sprintf(tt_gettext("err.LOG_PUSH_CERT_FAILURE_%s"),
                                    tt_gettext("err.LOG_PUSH_MANAGED_CERT_LOCATION"));
                                break;
                            case "unmanaged-certs":
                                $rtn = sprintf(tt_gettext("err.LOG_PUSH_CERT_FAILURE_%s"),
                                    tt_gettext("err.LOG_PUSH_UNMANAGED_CERT_LOCATION"));
                                break;
                            case "network":
                                $rtn = tt_gettext("err.LOG_PUSH_NETWORK_FAILURE");
                                break;
                            default:
                                $rtn = tt_gettext("err.LOG_PUSH_UNSPECIFIED_FAILURE");
                        }
                    }
                }
            }
        }
        return $rtn;
    }

    static public function is_log_sent($tracking_id)
    {
        $rtn = false;
        $status = self::get_log_status($tracking_id);

        if($status == "complete")
        {
            $rtn = true;
        }
        return $rtn;
    }

    // looks up a given service in cdb, returns true | false
    static public function get_connector_enabled_state($rest_data_adapter)
    {
        $target_type = self::get_target_type($rest_data_adapter);
        $table_name = "c_mgmt_system_enabledServicesState";

        $enabled = false;
        $root = $rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/" . $table_name);
        if(isset($root->record[0]))
        {
            $record = $root->record[0];
            $decoded = json_decode($record->value);

            if($decoded)
            {
                foreach($decoded as $service_name => $service_enabled)
                {
                    if($service_name == $target_type && $service_enabled == "true")
                    {
                        $enabled = true;
                        break;
                    }
                }
            }
            else
            {
                TTLOG_ERROR( getDeveloperLogger(), "Management Connector: No JSON configuration could be read from DB, location: " . $table_name);
            }
        }

        return $enabled;
    }

    // checks if we're currently registered by checking for a c_mgmt in active service list.
    static public function is_registered($rest_data_adapter)
    {
        return self::get_connector_enabled_state($rest_data_adapter);
    }

    // dangerously similar to get_connector_enabled_state("c_mgmt", $rest_data_adapter),
    // except we detect the difference between missing status -> defused, and status = false -> defusing
    static public function get_defused_state($rest_data_adapter)
    {
        $target_type = self::get_target_type($rest_data_adapter);
        $table_name = "c_mgmt_system_enabledServicesState";
        $root = $rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/" . $table_name);
        if(isset($root->record[0]))
        {
            $record = $root->record[0];
            $decoded = json_decode($record->value);
            if ($decoded && isset($decoded->c_ccucmgmt))
            {
                if( (string)$decoded->c_ccucmgmt == "true")
                {
                    return "fused";
                }
                else
                {
                    return "defusing";
                }
            }
            if ($decoded && isset($decoded->c_mgmt))
            {
                if( (string)$decoded->c_mgmt == "true")
                {
                    return "fused";
                }
                else
                {
                    return "defusing";
                }
            }
        }
        // If we have not found the status or could not decode the jsonblob assume defused. 
        return "defused";
    }

    static public function is_not_configured($rest_data_adapter, $name)
    {
        $table_name = "c_mgmt_system_configuredServicesState";
        $root = $rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/" . $table_name);
        if(isset($root->record[0]))
        {
            $record = $root->record[0];
            $decoded = json_decode($record->value);
            if($decoded)
            {
                foreach($decoded as $service_name => $service_configured)
                {
                    if($service_name == $name && $service_configured == "false")
                    {
                        return true;
                    }
                }
            }
        }
        // If we didn't find "false" for <connector>_configured_status then we can't be sure we're not_configured
        return false;
    }

    // Returns a text object (with or without hyperlinks. Based on a standard json fusion error format)
    // e.g.  CommandError: {"params": {"https://hercules-a.wbx2.com/v1/machine_accounts": "", "txt.PING": "ping", "txt.PROXY": "fusionproxy", "txt.DNS": "dns"}, "label": "err.URL_CONNECTION_ERROR_%s_%s_%s"}
    static public function formatErrorParams($command_error)
    {
        $pattern = '/CommandError: /';
        $error_string = preg_replace($pattern, '', $command_error);

        $error_label = '';
        $error_params = '';

        $json = json_decode($error_string);
        if( $json && isset($json->label))
        {
            $error_label = $json->label;
            if( isset($json->params))
            {
                $error_params = $json->params;

                $token_links = array();
                foreach ($error_params as $key => $value)
                {
                    $token_links[tt_gettext($key)] = $value;
                }

                $error = new TextWithHyperLinks("", tt_gettext($error_label), $token_links, "", true);
                return $error;
            }
            else
            {
                return new Text(tt_gettext($error_label));
            }
        }
        else
        {
            return new Text(tt_gettext($error_string));
        }
    }

    static private function create_bullet_point($label)
    {
        $container = new Container("", "li");
        $container->addWidget($label);
        $container->addCSSclass("registration_indent");
        return $container;
    }

    static public function create_goto_cloud_form($rest_data_adapter, $isExpresswayEnabled)
    {
        // init cloud form
        $target_type = self::get_target_type($rest_data_adapter);
        $actionlink = "fusionregistration";
        if($target_type != 'c_mgmt')
        {
            $actionlink = "cloudregistration";
        }
      
        $cloud_form = new DataForm( $actionlink, "", "dataform", "" );

        // renderable submit button created below
        $cloud_form->removeDefaultSubmitButton();
        if($target_type == "c_mgmt" && !$isExpresswayEnabled)
        {
            $fieldset = $cloud_form->createFieldset("fieldset.CLOUD_FUSION_SERVICES");
        }
        else
        {
            $fieldset = $cloud_form->createFieldset("fieldset.CLOUD_SERVICES");
        } 
        // form doesn't need labels. This makes messages more readable
        $fieldset->hide_labels();

        $not_registered_message = new Label(tt_gettext("lbl.FUSION_NOT_REGISTERED"));
        $fieldset->addRow("", $not_registered_message);

        $goto_cloud_text = new Label(tt_gettext("lbl.BOOTSTRAP_MISSING_TITLE"));
        $goto_cloud_text->setBold();
        $fieldset->addRow("", $goto_cloud_text);

        $table_widget = new Container("");
        $link = tt_gettext("link.CISCO_CLOUD_COLLABORATION_PORTAL");
        $bootstrap_needed = new TextWithHyperLinks("", tt_gettext("lbl.BOOTSTRAP_MISSING"), [$link => $link]);
        $table_widget->addWidget($bootstrap_needed);
        $table_widget->addCSSclass("registration_indent");
        $fieldset->addRow("", $table_widget);

        return $cloud_form;
    }

    static public function create_bootstrap_form($rest_data_adapter)
    {
        // init bootstrap form
        $target_type = self::get_target_type($rest_data_adapter);
        $actionlink = "fusionregistration";
        if($target_type != 'c_mgmt')
        {
            $actionlink = "cloudregistration";
        }
        $bootstrap_form = new DataForm( $actionlink, "", "dataform", "" );

        // renderable submit button created below
        $bootstrap_form->removeDefaultSubmitButton();
        if($target_type != 'c_mgmt')
        {
            $fieldset = $bootstrap_form->createFieldset("fieldset.CLOUD_SERVICES");         
        }
        else
        {
            $fieldset = $bootstrap_form->createFieldset("fieldset.CLOUD_FUSION_SERVICES");
        }
        // form doesn't need labels. This makes messages more readable
        $fieldset->hide_labels();

        $registration_ready = new Label(tt_gettext("lbl.FUSION_BOOTSTRAP_READY"));
        $fieldset->addRow("", $registration_ready);

        $bootstrap_text = new Label(tt_gettext("lbl.FUSION_BOOTSTRAP_TITLE"));
        $bootstrap_text->setBold();
        $fieldset->addRow("", $bootstrap_text);

        $widget = new Label(tt_gettext("lbl.FUSION_CA_EXPLANATION"));
        $widget->addCSSclass("registration_indent");
        $fieldset->addRow("", $widget);

        // a tickbox to determine whether we should trust cisco to handle our CAs 
        $container = new Container(""); 
        $ca_tickbox = new tickbox("use_fusion_ca", "use", "", "");
        $container->addWidget($ca_tickbox);
        $ca_confirmation_label = new Label(tt_gettext("lbl.FUSION_CA_CONFIRMATION_MESSAGE"));
        $ca_confirmation_label->addCSSclass("tickbox_additional_spacing");

        $container->addWidget($ca_confirmation_label); 
        $container->addCSSclass("registration_indent");
        $fieldset->addRow("", $container);

        $upgrade_message = new Label(tt_gettext("lbl.FUSION_MANAGEMENT_CONNECTOR_UPGRADE"));
        $upgrade_message->addCSSclass("registration_indent");
        $fieldset->addRow("", $upgrade_message);

        $message = tt_escape_quotes_for_js(tt_gettext("msg.C_MGMT_BOOTSTRAPPING"));
        $container = new Container("");
        $bootstrap_button = $bootstrap_form->getRenderableSubmitButton(
            "btn.BOOTSTRAP_FMC", "trigger_loader_gif( '$message' );return true;", "register");
        $container->addWidget($bootstrap_button);
        $bootstrap_widget = $container;
        $fieldset->addRow("Bootstrap", $bootstrap_widget);

        return $bootstrap_form;
    }

    static public function create_register_form($rest_data_adapter, $isExpresswayEnabled)
    {
        // init registration form
        $target_type = self::get_target_type($rest_data_adapter);
        $actionlink = "fusionregistration";
        if($target_type != 'c_mgmt')
        {   
            $actionlink = "cloudregistration";
        } 
        $registration_form = new DataForm( $actionlink, "", "dataform", "" );

        // renderable submit button created below
        $registration_form->removeDefaultSubmitButton();
        if($target_type != 'c_mgmt')
        {
            $fieldset = $registration_form->createFieldset("fieldset.CLOUD_SERVICES");         
        }
        else
        {
            $fieldset = $registration_form->createFieldset("fieldset.CLOUD_FUSION_SERVICES");
        }
        
        // form doesn't need labels. This makes messages more readable
        $fieldset->hide_labels();

        $registration_ready = new Label(sprintf(tt_gettext("lbl.FUSION_REGISTRATION_READY"), self::get_target_service($rest_data_adapter, $isExpresswayEnabled)));
        $fieldset->addRow("", $registration_ready);

        if(self::are_fusion_certs_installed())
        {
            // use certs link
            $cert_text = "lbl.FUSION_CERTS_ARE_ACCEPTED_%s";
        }
        else
        {
            // refuse certs link
            $cert_text = "lbl.FUSION_CERTS_ARE_NOT_ACCEPTED_%s";
        }

        $cert_link = new TextWithHyperLinks("", tt_gettext($cert_text), 
            array(tt_gettext("ttl.FUSION_CERT_TOOL") => "fusioncerts"));

        $fieldset->addRow("", $cert_link);

        $redirect_warning_message = new Label(tt_gettext("lbl.FUSION_REDIRECT_WARNING"));
        $fieldset->addRow("", $redirect_warning_message);

        $message = tt_escape_quotes_for_js(tt_gettext("msg.C_MGMT_INSTALLING"));
        $container = new Container("");
        $register_button = $registration_form->getRenderableSubmitButton(
            "btn.REGISTER_FUSION_SERVICES", "trigger_loader_gif( '$message' );return true;", "register");
        $container->addWidget($register_button);
        $register_widget = $container;
        $fieldset->addRow("Register", $register_widget);

        return $registration_form;
    }

    static public function get_target_service($rest_data_adapter, $isExpresswayEnabled)
    {
        $target_type = self::get_target_type($rest_data_adapter);
        if($target_type == "c_mgmt" && !$isExpresswayEnabled)
        {
            $registered_tt = sprintf(tt_gettext("ttl.CLOUD_FUSION"), $target_type);
            return $registered_tt;
        }
        else {
            $registered_tt = sprintf(tt_gettext("ttl.CLOUD_SERVICES"), $target_type);
            return $registered_tt;
        }

    }

    //targetType is used as a criteria for managment connector to decide which service it is running as part of.
    static public function get_target_type($rest_data_adapter)
    {
        $target_type = $rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_targetType");
        if($target_type->num_recs[0] > 0)
        {
           $target_value = $target_type->record[0]->value;
           return str_replace('"', '', $target_value);
        }
        return 'c_mgmt';
    }

    static private function set_curl_options($ch, $decoded_json_conf) {
        $ca_cert = $decoded_json_conf->certs->ca;
        curl_setopt($ch, CURLOPT_USERAGENT, "FMC");
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_CAINFO, $ca_cert);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/json"));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

        $proxy_settings = $decoded_json_conf->proxy;
        // configure proxy if being used
        if ($proxy_settings && isset($proxy_settings->enabled) && ($proxy_settings->enabled == "true"))
        {
            curl_setopt($ch, CURLOPT_PROXY, $proxy_settings->address . ":" . $proxy_settings->port);
            curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxy_settings->username . ":" . taa_crypto_decrypt($proxy_settings->password));
        }

        return $ch;
    }

    static public function get_latest_package_info($decoded_json_conf) {
        $target_type = $decoded_json_conf->system->targetType;
        if($target_type == 'c_ccucmgmt')
        {
            $ch = curl_init($decoded_json_conf->oauth->atlasUrlPrefix . "/hercules/api/v2/channels/latest/packages/c_ccucmgmt");
        }
        else
        {
            $ch = curl_init($decoded_json_conf->oauth->atlasUrlPrefix . "/hercules/api/v2/channels/stable/packages/c_mgmt");
        }
        $ch = self::set_curl_options($ch, $decoded_json_conf);
        curl_setopt($ch, CURLOPT_POST, 0);
        $result = curl_exec($ch);
        if ($result === false)
        {
            $result = sprintf(tt_gettext("err.FUSION_MANAGEMENT_CONNECTOR_UPGRADE_ERROR"), curl_error($ch));
        }
        curl_close($ch);
        return $result;
    }

    static public function download_file($url, $local_path, $decoded_json_conf) {
        $fp = fopen($local_path, 'w');
        $ch = curl_init($url);
        $ch = self::set_curl_options($ch, $decoded_json_conf);
        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_exec($ch);
        curl_close($ch);
        fclose($fp);
	}

    static public function get_c_mgmt_version()
    {
        $cmd = "dpkg -s c_mgmt | grep Version";
        $result = shell_exec($cmd);
        $comp = preg_split('/ +/', $result);

        return rtrim($comp[1]);
    }

    static public function on_latest_c_mgmt($rest_data_adapter)
    {
        $decoded_json_conf = self::read_json_config_file();
        if( $decoded_json_conf )
        {
            $latest_package_response = self::get_latest_package_info($decoded_json_conf);
            $json_latest_package = json_decode($latest_package_response);
            if (isset($json_latest_package))
            {
                if (self::get_c_mgmt_version() == $json_latest_package->version)
                {
                    return true;
                }
            }
        }
        return false;
    }

    static private function read_json_config_file()
    {
        $json_conf_location = "/opt/c_mgmt/etc/config/c_mgmt.json";
        if(!file_exists($json_conf_location))
        {
            die();
        }

        $json_conf = file_get_contents($json_conf_location);
        return json_decode($json_conf);
    }
}

?>
