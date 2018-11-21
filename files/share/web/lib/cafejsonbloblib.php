<?php
require_once( getenv("PHP_LIBDIR") . "/restcommand.php" );

/*
* This library class is for interacting with json blob data in the cdb.
* The principle reason for storing data like this is to have scema less data
* This is required for cafe applications. 
*/
class BlobLibrary
{
    // if not a cafe product these must be changed
    public static $cdb_path = "/configuration/cafe/cafeblobconfiguration/";
    public static $xcommand = "cafe";

    // Takes everything of name, divides into rows and returns as an array of associative arrays
    protected static function grab_blob($rest_data_adapter, $name)
    {
        // grab everything
        $path = self::$cdb_path . "name/$name";
        $root = $rest_data_adapter->get($path);

        // cycle through grabbing the decoded json objects
        $json_objects = array();
        foreach($root->record as $record)
        {
            $json = (string)$record->value;
            $decoded = json_decode($json);
            if($decoded)
            {
                if(is_array($decoded))
                {
                    // returned a list of objects
                    foreach($decoded as $row)
                    {
                        $json_objects[] = $row;
                    }
                }
                else
                {
                    // returned a single object
                    $json_objects[] = $decoded;
                }
            }
            else
            {
                TTLOG_WARN( getDeveloperLogger(), "error: fusion blob read fail, info: non-json provided, dump: " . $json);
            }
        }

        // convert json objects to associative arrays.
        $return_array = array();
        foreach($json_objects as $json_object)
        {
            if(is_object($json_object))
            {
                $params = get_object_vars($json_object);
                if($params)
                {
                    $return_array[] = $params;
                }
            }
            else
            {
                TTLOG_WARN( getDeveloperLogger(), "error: fusion blob read fail, info: non-object provided, dump: " . print_r($json_object));
            }
        }
        return $return_array;
    }

    // returns array of records (associative arrays, fieldname => value)
    public static function get_list($rest_data_adapter, $name)
    {
        return self::grab_blob($rest_data_adapter, $name);
    }

    // returns single record (associative array, fieldname => value) or null if record not found
    public static function get_row($rest_data_adapter, $name, $index_field, $index)
    {
        $list_return = self::grab_blob($rest_data_adapter, $name);
        foreach ($list_return as $row)
        {
            if($row[$index_field] === $index)
            {
                return $row;
            }
        }
        return null;
    }

    // returns single record (associative array, fieldname => value) or null if record not found
    public static function get_one($rest_data_adapter, $name)
    {
        $list_return = self::grab_blob($rest_data_adapter, $name);
        if(isset($list_return[0]))
        {
            return $list_return[0];
        }
        return null;
    }

    // runs blob xcommand, 
    public static function run_xcommand($rest_data_adapter, $connector, $command_name, $params)
    {

        if(!is_string($params))
        {
            $params = json_encode($params);
        }

        $command_params = array(
            "connector" => $connector,
            "connector_cmd" => $command_name,
            "parameters" => $params);
        $command = new RestCommand($rest_data_adapter, self::$xcommand, $command_params);
        $result = $command->start();
        $results = $result->results();

        if ($result->error)
        {
            $error = $result->error;
            $response = array(false, $error);
            return $response;
        } else {
            $infos = array();
            foreach($results as $info)
            {
                $infos[] = $info['info'];
            }
            $info_string = implode(", ", $infos);
            return array(true, $info_string);
        }
    }
}


?>
