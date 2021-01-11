<?php
require_once( getenv("PHP_LIBDIR") . "/applicationpage.php" );
require_once( getenv("PHP_LIBDIR") . "/cafejsonbloblib.php" );

require_once( getenv("PHP_LIBDIR") . "/fusionlib.php" );

class HybridServicesSendLogsPage extends ApplicationPage
{
    private $form = false;
    private $reload_from_postdata = false;

    private $labels = array(
            "sr_number" => "lbl.HYBRID_SERVICE_REQUEST");

    private $blob_name = "c_mgmt_logging_identifier";

    protected function init()
    {

        $privileges = $this->IProduct->getPrivileges();
        $privname = "fused";

        $key = in_array($privname, $privileges);

        if ($key)
        {
            $this->updateData();
            $this->initForm();

            $this->view->inline_javascript[] = $this->_get_javascript();
        }
        else
        {
            # If the Fused privilege isn't present do not display page, as feature is not supported.
            # You must be fused and on an 8.8 Expressway, for Posting logs to work.
            $this->send_404();
        }

    }

    protected function getHardwareSerialNumber()
    {
        return $this->IProduct->getSerialNumber();
    }

    private function initForm()
    {

        $this->form = new DataForm( "", "", "send_log_form" );
        $this->form->removeDefaultSubmitButton();

        $log_fieldset = $this->form->createFieldset("lbl.HYBRID_SERVICES_LOG_FIELDSET");

        $confirmSendJs = 'return confirm_send(form);';
        $button = $this->form->addSubmitButton("btn.SEND", $confirmSendJs);

        $info_fieldset = $this->form->createFieldset("lbl.HYBRID_SERVICES_INFO_FIELDSET");

        // Serial Number of Machine
        $log_fieldset->addRow( tt_gettext("lbl.HYBRID_SERIAL_NUMBER"), new Label ( $this->getHardwareSerialNumber() ) );
        $info_fieldset->addRow("", new LongLabel( tt_gettext("lbl.HYBRID_SERVICES_INFORMATION") ) );
        $info_fieldset->hide_labels();

    }

    function gen_uuid()
    {
        $data = openssl_random_pseudo_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    private function updateData()
    {
        if (isset($_POST['submitbutton']))
        {
            // Generate a Tracking ID
            $tracking_id = $this->gen_uuid();

            $verified_data = array("uuid" => $tracking_id);

            $post_json = json_encode($verified_data);

            $response = $this->rest_data_adapter->put_array(array("name" => $this->blob_name, "value" => $post_json),
                    "configuration/cafe/cafeblobconfiguration/name/" . $this->blob_name);

            $timeout = 120;
            $log_push_record = $this->rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_logging_timeout");
            if(isset($log_push_record->record[0]))
            {
                $timeout = (int)$log_push_record->record[0]->value;
            }

            if($this->poll_on_log_sent($timeout, $tracking_id))
            {
                $search_message = sprintf(tt_gettext("lbl.HYBRID_LOG_SEARCH_STRING"), $tracking_id);

                $this->addError(new InfoMessage(tt_gettext("err.SUCCESS_SHORT_TITLE"), $search_message));
                success_redirect();
            }
            else
            {
                $status = FusionLib::get_log_status($tracking_id);
                if($status == false)
                {
                    $status = "error";
                }

                $fail_message = sprintf(tt_gettext("err.HYBRID_SERVICES_LOG_TIMED_OUT_%s_%s_%s"), $timeout, $tracking_id, $status);

                $this->addError(new InfoMessage(tt_gettext("err.ERROR_TITLE"), $fail_message));
                redirect();
            }

        }
    }

    function writeContent()
    {
        $this->form->render();
    }


    function poll_on_log_sent($timeout, $tracking_id)
    {
        # Loop checking if the tracking_id state is 'complete' for posting logs to cloud.
        $attempts = 0;
        while($attempts < $timeout)
        {
            if(FusionLib::is_log_sent($tracking_id))
            {
                return true;
            }
            sleep(1);
            $attempts++;
        }
        return false;
    }


    private function _get_javascript()
    {
        $txt_CONFIRM_SEND_LOG = tt_escape_quotes_for_js(tt_gettext('msg.HYBRID_SERVICES_LOG_CONFIG'));

        $timeout = 120;
        $log_push_record = $this->rest_data_adapter->get_local("configuration/cafe/cafeblobconfiguration/name/c_mgmt_logging_timeout");
        if(isset($log_push_record->record[0]))
        {
            $timeout = $log_push_record->record[0]->value;
        }

        $spinner_text = sprintf(tt_gettext("lbl.HYBRID_SERVICES_LOG_SENDING_%s"), $timeout);

        $code = <<<EOT
            function confirm_send(f)
            {
                sendlogform = f;
                return tt_confirm("$txt_CONFIRM_SEND_LOG", "trigger_loader_gif('$spinner_text');sendlogform.submit()");
            }
EOT;
        return $code;
    }


    private function send_404()
    {
        http_response_code(404);
        echo "<h1>Not Found</h1>\n";
        echo "<p>The requested URL " . htmlspecialchars($_SERVER['REQUEST_URI']) . " was not found on this server.</p>\n";
        die();
    }


}

$page = new HybridServicesSendLogsPage();
$page->render();

?>
