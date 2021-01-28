<?php

class ManagementLib
{
    static public function generate_safe_key($key_length=30)
    {
        return base64_encode(openssl_random_pseudo_bytes($key_length));
    }
    static public function base64_url_encode($input)
    {
        return strtr(base64_encode($input), '+/', '-_');
    }
    static public function read_json_config_file()
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
    // decrypt aes encrypted returned data
    static public function decrypt_get_var($get_var, $shared_key, $iv)
    {
        $get_var = urldecode($get_var);

        // openssl module takes base64 encoded form, but we must swap out url base64 chars first
        $get_var = strtr($get_var, '-_', '+/');
        return openssl_decrypt($get_var, 'aes-256-cbc', base64_decode($shared_key), 0, base64_decode($iv));
    }

    // returns true if $version1 is different than $version2
    static public function is_app_version_different($version1, $version2)
    {
        $version1_array = $get_array_form_of_version($version1);
        $version2_array = $get_array_form_of_version($version2);

        foreach ($version1_array as $key => $value)
        {
            if(!array_key_exists($key, $version2_array) || (int)$value != (int)$version2_array[$key]) {
                return true;
            }
        }
        return false; // the same version.
    }
    public function get_array_form_of_version($version)
    {
        if(strpos($version, "-") !== false) {
            $version = substr($version, strpos($version, "-")+1);
        }
        return explode(".", $version);
    }
    static public function remove_blocked_versions($service, $rest_data_adapter)
    {
        $root = $rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_installed_blacklist");
        if(isset($root->record[0])) {
            $record = $root->record[0];
            $decoded = json_decode($record->value);
            if($decoded && isset($decoded->{$service}) ) {
                unset($decoded->{$service});
                $post = json_encode($decoded);
                $rest_data_adapter->put_array(
                    array("value" => $post),
                    "configuration/cafe/cafeblobconfiguration/name/c_mgmt_installed_blacklist"
                );
                return true;
            }
        }
        return false;
    }
    static public function get_blocked_versions($service, $rest_data_adapter)
    {
        $root = $rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_installed_blacklist");
        if(isset($root->record[0])) {
            $record = $root->record[0];
            $decoded = json_decode($record->value);
            if($decoded && isset($decoded->{$service}) ) {
                return $decoded->{$service}->version;
            }
        }
        return null;
    }
    static public function get_blocked_rollback_details($service, $rest_data_adapter)
    {
        $root = $rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_rollback_blacklist");
        if(isset($root->record[0])) {
            $record = $root->record[0];
            $decoded = json_decode($record->value);
            if($decoded && isset($decoded->{$service}) ) {
                return $decoded->{$service}->version;
            }
        }
        return null;
    }
    static public function get_rollback_details($service)
    {
        $previous_dir = "/mnt/harddisk/persistent/fusion/previousversions";
        $file_pattern = "$previous_dir/$service*.tlp";

        $file_name = glob($file_pattern);
        if ($file_name && isset($file_name[0])) {
            $version = self::get_version_from_filename($file_name[0]);
            if(isset($version)) {
                return $version;
            }
        }
        return null;
    }
    static public function get_version_from_filename($filename)
    {
        $end = strrpos($filename, "_");
        $start = $end+1;
        $end = strrpos($filename, ".");

        $version= substr($filename, $start, $end-$start);
        if (isset($version)) {
            return $version;
        }
        return null;
    }
    static public function get_alarm_range($service)
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
    static public function get_alarms_for_service($service, $rest_data_adapter)
    {
        list($start, $end) = self::get_alarm_range($service);
        $alarm_root = $rest_data_adapter->get("/status/alarm");
        $alarms = array();
        foreach($alarm_root->record as $record)
        {
            if($record->id >= $start && $record->id <= $end && (string)$record->status != "lowered") {
                $alarms[(string)$record->id] = $record;
            }
        }
        return $alarms;
    }
    static public function revive_required($rest_data_adapter)
    {
        $root = $rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_reRegisterRequired");
        return (int)$root->num_recs > 0 && $root->record[0]->value == '"true"';
    }
    static public function get_rollback_confirmation_js($type)
    {
        if ($type == "ROLLBACK") {
            $txt_ROLLBACK_CONFIRM = tt_escape_quotes_for_js(tt_gettext('msg.ROLLBACK_CONFIRM'));
        }
        else
        {
            $txt_ROLLBACK_CONFIRM = tt_escape_quotes_for_js(tt_gettext('msg.ROLLFORWARD_CONFIRM'));
        }
        $code = <<<EOT
            function confirm_rollback(f)
            {
                rollbackform= f;
                return tt_confirm("$txt_ROLLBACK_CONFIRM", "rollbackform.submit()");
            }
EOT;
        return $code;
    }
    static public function is_hostname_and_domain_set($rest_data_adapter)
    {
        $DNSConfiguration = $rest_data_adapter->get_local("configuration/dns");
        $dnsHost = $DNSConfiguration->record[0]->host_name;
        $dnsDomain = $DNSConfiguration->record[0]->domain_name;
        return $dnsHost != "" && $dnsDomain != "";
    }
}

?>
