<?php

require_once( getenv("PHP_LIBDIR") . "/datatableform.php" );
require_once( getenv("PHP_LIBDIR") . "/datatablewrapper.php" );
require_once( getenv("PHP_LIBDIR") . "/ajaxstatus.php");

require_once( getenv("PHP_LIBDIR") . "/internalconnection.php" );
require_once( getenv("PHP_LIBDIR") . "/widgets/statuswidget.php");
require_once( getenv("PHP_LIBDIR") . "/widgets/textwithhyperlinks.php");
require_once( getenv("PHP_LIBDIR") . "/widgets/hyperlink.php");


class FusionStatus extends AjaxStatus
{
    private $rest_data_adapter;
    protected $setEvalScripts = true;
    static private $config_path = "/mnt/harddisk/current/fusion/config_links/";

    // PUBLIC

    final public function __construct($rest_data_adapter )
    {
        $this->rest_data_adapter = $rest_data_adapter;
    }

    public static function get_service_status_blob()
    {
        // checks to see if status exists for any of the elements
        $path = "/Cafe/c_mgmt/additional/connectors/";
        $url = "getxml?location=";
        $result = InternalConnection::read($url . "/Status" . $path);
        $result = simplexml_load_string($result);
        return InternalConnection::select_node($result, $path);
    }

    public static function get_service_enabled($rest_data_adapter, $service)
    {
        $service_on_root = $rest_data_adapter->get_local("configuration/service/name/" . $service );
        $enabled = false;
        if(isset($service_on_root->record[0]) &&
            (string)$service_on_root->record[0]->mode === "on")
        {
            $enabled = true;
        }
        return $enabled;
    }

    /*   
        If $all_details is false we return associative array: token => "link"
            only returning config links.
        If $all_details is true we return list: details_array
    */

    public static function get_related_tasks($service, $all_details = false)
    {
        $config_file = self::$config_path . $service . ".json";
        $related_tasks = array();

        if( file_exists($config_file))
        {
            $json = file_get_contents($config_file);
            $decoded = json_decode($json);
            if($decoded && !empty($decoded))
            {
                foreach($decoded as $token => $details)
                {
                    // support legacy format
                    if(is_string($details))
                    {
                        $details = (object)array(
                            "configure_token" => $token,
                            "location" => $details
                        );
                    }

                    if($all_details)
                    {
                        $related_tasks[] = $details;
                    }
                    else if(isset($details->configure_token))
                    {
                        $related_tasks[$details->configure_token] = $details->location;
                    }
                }
            }
        }
        return $related_tasks;
    }

    public static function create_status_label($status_node, $alarm_number)
    {
        $composed_status = $status_node->composed_status;
        $status = new StatusWidget(tt_gettext("lbl.CONNECTOR_NOT_INSTALLED"), "error");

        $status_type = "";
        if($alarm_number > 0)
        {
            $status_type = "error";
        }

        if($composed_status == "uninstalling")
        {
            $status = tt_gettext("lbl.CONNECTOR_UNINSTALLING");
        }   
        else if($composed_status == "installing")
        {
            $status = tt_gettext("lbl.CONNECTOR_INSTALLING");
        }
        else if($composed_status == "downloading")
        {
            $status = tt_gettext("lbl.CONNECTOR_DOWNLOADING");
        }
        else if($composed_status == "not_installed")
        {
            $status = tt_gettext("lbl.CONNECTOR_NOT_INSTALLED");
        } 
        else if($composed_status == "not_configured")
        {
            $status = tt_gettext("lbl.CONNECTOR_NOT_CONFIGURED");
        }
        else if($composed_status == "disabled")                    
        { 
            $status = tt_gettext("lbl.CONNECTOR_DISABLED");
        }
        else if($composed_status == "running")
        {
            if ($alarm_number > 0)
            {
                $status = tt_gettext("lbl.CONNECTOR_RUNNING_WITH_ALARMS");
            }
            else
            {
                $status_type = "info";
                $status = tt_gettext("lbl.CONNECTOR_RUNNING");
            }
        }
        else if($composed_status == "stopped")
        {
            $status = tt_gettext("lbl.CONNECTOR_STOPPED");
        }

        if(!$status_type)
        {
            return $status;
        }
        else
        {
            return new StatusWidget($status, $status_type);
        }
        
    }

    public function getStatusTable()
    {
         // services table takes all the entitled services from cafeblob
        $service_list = array();

        $root = $this->rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_entitledServices");
        if(isset($root->record[0]))
        {
            $record = $root->record[0];
            $decoded = json_decode($record->value);

            if($decoded)
            {
                $service_list = $decoded;
            }
        }

        $connector_status = self::get_service_status_blob();

        $alarm_column_needed = false;

        // builds row_data, checking to see if service is running.
        $records = array();
        foreach($service_list as $service_struct)
        {
            if(is_string($service_struct->{'name'}))
            {
                $service = $service_struct->{'name'};
                $display_name = $service_struct->{'display_name'};
                $version = "-";
                $alarm_number = 0;
                $alarm_text = tt_gettext("lbl.SERVICE_NO_ALARMS");
                $new_record = array();
                $new_record['name'] = $display_name;

                $new_record['uuid'] = $service;

                $status = new StatusWidget(tt_gettext("lbl.CONNECTOR_NOT_INSTALLED"), "error");

                if(isset($connector_status->{$service}))
                {
                    $status_node = $connector_status->{$service};

                    if( $status_node->version != "None")
                    {
                        $version = $status_node->version;
                    }

                    if( isset($status_node->alarms) )
                    {
                        $alarm_number = (int)$status_node->alarms;
                        if ($alarm_number > 0)
                        {
                            $alarm_text = sprintf(tt_ngettext('lbl.SERVICE_ALARMS_%d','lbl.SERVICE_ALARMS_%d.plural', $alarm_number), $alarm_number);
                            $alarm_text = new hyperlink("", $alarm_text, "fusionregistration?uuid=" . $service);
                            $alarm_column_needed = true;
                        }
                    }

                    $status = self::create_status_label($status_node, $alarm_number);
                }


                $config_pages = self::get_related_tasks($service);
                if(!empty($config_pages))
                {
                    $percent_s_list = array();
                    foreach($config_pages as $token => $link)
                    {
                        $percent_s_list[] = "%s";
                    }
                    $new_record["config_links"]= new TextWithHyperLinks("", implode(" | ", $percent_s_list), $config_pages);
                }
                else
                {
                    $new_record["config_links"] = "";
                }

                $new_record['version'] = $version;
                $new_record['alarms'] = $alarm_text;
                $new_record["status"] = $status;

                // c_mgmt should never be able to be enabled / disabled
                $new_record['service'] = $service;
                if($service === "c_mgmt")
                {
                    $new_record['active'] = tt_gettext("Enabled");
                    array_unshift($records, $new_record); // prepend c_mgmt so it appears first by default
                }
                else
                {
                    $enabled = self::get_service_enabled($this->rest_data_adapter, $service);
                    $active = $enabled ? tt_gettext("Enabled") : tt_gettext("Disabled");
                    $new_record['active'] = new hyperlink("", $active, "fusionregistration?uuid=" . $service . "#enable_service");

                    $records[] = $new_record;
                }
            }
        }

        // draws table (includes refresh, enable/disable buttons, no new or delete buttons)
        $headings = array( tt_gettext("Service") => 'name',
                           tt_gettext("Status") => 'status',
                           tt_gettext("Version") => 'version',
                           tt_gettext("Active") => 'active',
                           tt_gettext("Configuration") => 'config_links');

        if( $alarm_column_needed )
        {
            // Do this trick to insert into array, PHP has no such function for associative elements
            $first_elements = array_splice($headings, 0, 2);
            $headings = array_merge ($first_elements, array(tt_gettext("ttl.ALARMS") => 'alarms'), $headings); 
        }

        $services_table = new DataTableWrapper($headings);
        $services_table->setTableName("fusion_services");
        // have to hardcode url to return to, as this can be loaded by fusionajax page.
        $services_table->setLinkBase("fusionregistration");
        $services_table->set_listing_only(true);
        $services_table->set_link_id("service");
        $services_table->has_link_field("service");
        $services_table->suppressDefaultActions();
        $services_table->initialise(count($records));
        //$services_table->add_state_buttons();

        $services_table->add_rows($records);
        $services_table->table->disableSorting();

        return $services_table;
    }

    // Render function, is added so that this table can be a called as a widget
    public function render()
    {
        $this->renderWithAjaxElementId();
    }

    // Methods to contorl how often ajax status updates.
    protected function getFrequency()
    {
        return 6;
    }

    protected function getDecay()
    {
        return 1.5;
    }

    protected function getMaximumDelay()
    {
        // in seconds
        return 30;
    }

    protected function getHtmlId()
    {
        return 'fusion_ajax_table';
    }

    protected function getUrl()
    {
        return 'fusionajax';
    }
}

?>
