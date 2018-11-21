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
    static public function get_connector_enabled_state($name, $rest_data_adapter)
    {
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
                    if($service_name == $name && $service_enabled == "true")
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
        return self::get_connector_enabled_state("c_mgmt", $rest_data_adapter);
    }

    // dangerously similar to get_connector_enabled_state("c_mgmt", $rest_data_adapter),
    // except we detect the difference between missing status -> defused, and status = false -> defusing
    static public function get_defused_state($rest_data_adapter)
    {
        $table_name = "c_mgmt_system_enabledServicesState";
        $root = $rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/" . $table_name);
        if(isset($root->record[0]))
        {
            $record = $root->record[0];
            $decoded = json_decode($record->value);
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

    static private function get_portal_link_widget()
    {
        // attempt to find link in config file
        $link = null;
        $json_conf_location = "/opt/c_mgmt/etc/config/c_mgmt.json";
        if(file_exists($json_conf_location))
        {
            $json_conf = file_get_contents($json_conf_location);
            $decoded = json_decode($json_conf);
            if($decoded && isset($decoded->oauth->atlasAdminFusionPortal))
            {
                $link = $decoded->oauth->atlasAdminFusionPortal;
            }
        }

        // create a widget with a link if we found one.
        $not_registered_message = tt_gettext("lbl.FUSION_NOT_REGISTERED");
        $link_text = tt_gettext("link.CISCO_CLOUD_COLLABORATION_PORTAL");
        if($link)
        {
            return new TextWithHyperLinks("", $not_registered_message, [$link_text => $link]);
        }
        else
        {
            return new Label(sprintf($not_registered_message, $link_text));
        }
    }

    static public function create_registration_form($peer_data, $precheck_run=false, $server_visible=true, $certs_good=false, $proxy_configured=false)
    {
        // init registration form
        $registration_form = new DataForm( "fusionregistration", "", "dataform", "" );

        // renderable submit button created below
        $registration_form->removeDefaultSubmitButton();

        $fieldset = $registration_form->createFieldset("fieldset.CLOUD_FUSION_SERVICES");
        
        // form doesn't need labels. This makes messages more readable
        $fieldset->hide_labels();

        // register message depends on visibility to the cloud and whether proxy is configured.
        $fieldset->addRow("", self::get_portal_link_widget());
        
        // add a seperate message when in cluster
        if (count($peer_data) > 1) 
        {
            $peers = implode(",", array_keys($peer_data));
            $cluster_message = sprintf(tt_gettext("lbl.FUSION_CLUSTER"), $peers);   
            $fieldset->addRow("", new Label($cluster_message));
        }

        if($precheck_run && !$server_visible)
        {
            // add a button which retrys the connection. Encouraging users to fix problem and retry test.
            $registration_form->addSubmitButton( "btn.RETRY_FUSION_PRECHECK", "location.reload(true);return false;" );

            // add red opening line
            $widget = new Label(tt_gettext("lbl.PRECHECK_FAILED"));
            $widget->setBold();
            $widget = new StatusWidget($widget, "error");
            $fieldset->addRow("", $widget);

            // add explanation (without bullet point)
            $widget = new Label(tt_gettext("lbl.PRECHECK_FAILED_EXPLANATION"));
            $widget->addCSSclass("registration_indent");
            $fieldset->addRow("", $widget);

            // add three possible causes, all indented with bullet points
            $firewall_widget = new Label(tt_gettext("lbl.PRECHECK_TRY_FIREWALL"));
            $firewall_widget = self::create_bullet_point($firewall_widget);
            $fieldset->addRow("", $firewall_widget);

            $dns_link = new TextWithHyperLinks("", tt_gettext("lbl.PRECHECK_TRY_DNS_%s"), 
                array(tt_gettext("menu.DNS") => "dns"));
            $dns_link = new Label($dns_link->renderAsString());
            $dns_link = self::create_bullet_point($dns_link);
            $fieldset->addRow("", $dns_link);

            if($proxy_configured)
            {
                // proxy configured but not working
                $proxy_required_text = "lbl.PRECHECK_PROXY_BROKEN_%s";
            }
            else
            {
                // need proxy
                $proxy_required_text = "lbl.PRECHECK_TRY_PROXY_%s";
            }
            $proxy_link = new TextWithHyperLinks("", tt_gettext($proxy_required_text), 
                array(tt_gettext("ttl.FUSION_PROXY") => "fusionproxy"));
            $proxy_link = new Label($proxy_link->renderAsString());
            $proxy_link = self::create_bullet_point($proxy_link);
          
            $fieldset->addRow("", $proxy_link);
        }

        // add a bolded register title
        $register_text = new Label(tt_gettext("lbl.FUSION_CERT_REGISTER_TITLE"));
        $register_text->setBold();
        $fieldset->addRow("", $register_text);

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

        $redirect_warning_message = new Label(tt_gettext("lbl.FUSION_REDIRECT_WARNING"));
        $redirect_warning_message->addCSSclass("registration_indent");
        $fieldset->addRow("", $redirect_warning_message);

        $upgrade_message = new Label(tt_gettext("lbl.FUSION_MANAGEMENT_CONNECTOR_UPGRADE"));
        $fieldset->addRow("", $upgrade_message);

        $message = tt_escape_quotes_for_js(tt_gettext("msg.C_MGMT_INSTALLING"));
        $container = new Container("");
        $register_button = $registration_form->getRenderableSubmitButton(
            "btn.REGISTER_FUSION_SERVICES", "trigger_loader_gif( '$message' );return true;", "register");
        $container->addWidget($register_button);
        $register_widget = $container;
        $fieldset->addRow("Register", $register_widget);

        return $registration_form;
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
        $ch = curl_init($decoded_json_conf->oauth->atlasUrlPrefix . "/hercules/api/v2/channels/stable/packages/c_mgmt");
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

    static private function populate_service_entries($results, $rest_data_adapter)
    {
        $service_map = Array("idbroker" => "c_mgmt_system_idpHost_u2c",
                             "fms" => "c_mgmt_system_fmsUrl",
                             "atlasFusionAdminPortal" => "c_mgmt_system_atlas_portal_u2c");
                             
        if (isset($results))
        {
            foreach ($results['services'] as $service)
            {
                if (array_key_exists($service['serviceName'], $service_map)) {
                    $url = $service['logicalNames'][0];

                    // if the url is fms then the path needs to be stripped
                    if ($service['serviceName'] == "fms")
                    {
                        $parsed_url = parse_url($url);
                        $url = (isset($parsed_url['scheme']) ? "${parsed_url['scheme']}://" : "https://") .
                                $parsed_url['host'] .
                                (isset($parsed_url['port']) ? ":${parsed_url[port]}" : "");
                    }

                    // add service url to cdb
                    $rest_data_adapter->put_array(array("value" => '"' . $url . '"'),
                            "configuration/cafe/cafeblobconfiguration/name/" . $service_map[$service['serviceName']]);
                }
            }
        }
    }

    static public function update_service_catalog($rest_data_adapter)
    {
        // get service urls from u2c
        $json_conf_location = "/opt/c_mgmt/etc/config/c_mgmt.json";
        if (file_exists($json_conf_location)) {
            $json_conf = file_get_contents($json_conf_location);
            $decoded_json_conf = json_decode($json_conf);

            // configure curl data
            $url= $decoded_json_conf->u2c->u2cHost . $decoded_json_conf->u2c->serviceUrl;
            $proxy_settings = $decoded_json_conf->proxy;
            $ca_cert = $decoded_json_conf->certs->ca;
            $postdata = '{"email":"123@abc.com"}';

            // configure curl statement
            $ch = curl_init( $url );

            // configure proxy if being used
            if ($proxy_settings && isset($proxy_settings->enabled) && ($proxy_settings->enabled == "true"))
            {
                curl_setopt($ch, CURLOPT_PROXY, $proxy_settings->address . ":" . $proxy_settings->port);
                curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxy_settings->username . ":" . taa_crypto_decrypt($proxy_settings->password));
            }
            curl_setopt($ch, CURLOPT_USERAGENT, "FMC");
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($ch, CURLOPT_CAINFO, $ca_cert);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/json"));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);

            $result = curl_exec( $ch );

            // populate services with returned responses
            if ($result)
            {
                self::populate_service_entries(json_decode($result, true), $rest_data_adapter);
            }
        }
    }
}

?>
