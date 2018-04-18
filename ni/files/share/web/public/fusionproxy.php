<?php
require_once( getenv("PHP_LIBDIR") . "/applicationpage.php" );
require_once( getenv("PHP_LIBDIR") . "/cafejsonbloblib.php" );
require_once( getenv("PHP_LIBDIR") . "/hideshower.php" );

class FusionProxyPage extends ApplicationPage
{
    private $form = false;
    private $regexs = array(
            "enabled" => '/^(true|false)$/',
            "address" => '/^[^"\']{1,50}$/', // probably should be ipv4 or ipv6 or fqdn
            "port" => "/^[0-9]{1,5}$/",
            "username" => '/^[^"\']{0,50}$/',
            "password" => '/^[^"\']{0,50}$/');

    private $labels = array(
            "enabled" => "lbl.USE_FUSION_PROXY",
            "address" => "lbl.FUSION_PROXY_ADDRESS",
            "port" => "lbl.FUSION_PROXY_PORT",
            "username" => "lbl.FUSION_PROXY_USERNAME",
            "password" => "lbl.FUSION_PROXY_PASSWORD");

    private $blob_name = "c_mgmt_https_proxy";
    private $reload_from_postdata = false;

    public function get_page_title_for_help()
    {
        return "connectorproxy";
    }

    protected function init()
    {
        $this->updateData();
        $this->initForm();
    }

    private function initForm()
    {
        $this->form = new DataForm( $_SERVER['REQUEST_URI'], "validate", "dataform" );
        $fieldset = $this->form->createFieldset("lbl.FUSION_PROXY_FIELDSET");

        $values = array(
            "enabled" => "false",
            "address" => "",
            "port" => "",
            "username" => "",
            "password" => "");

        // read from c_mgmt_https_proxy
        $data = BlobLibrary::get_one($this->rest_data_adapter, $this->blob_name);
        if($data)
        {
            $values = array_merge($values, $data);
        }

        // enabled dropdown
        $enabled_widget = new DropDownBox("enabled", $values['enabled'], tt_gettext("doc.USE_FUSION_PROXY"));
        $enabled_widget->setValues(array("false" => tt_gettext("No"), "true" => tt_gettext("Yes")));
        $enabled_widget->disableIfReadOnly($this->user);
        $fieldset->addRow($this->labels["enabled"], $enabled_widget);

        // address textbox
        $address_widget = new TextBox("address", $values['address'], 30, 50, tt_gettext("doc.FUSION_PROXY_ADDRESS"));
        $address_widget->setRequiredJavascript("String", true, 0, 50);
        $address_widget->disableIfReadOnly($this->user);

        $fieldset->addRow($this->labels["address"], $address_widget, "address_row");

        // port textbox, integer valuspace
        $port_widget = new TextBox("port", $values['port'], 6, 6, tt_gettext("doc.FUSION_PROXY_PORT"));
        $port_widget->setRequiredJavascript("Integer", true, 0, 65535);
        $port_widget->disableIfReadOnly($this->user);

        $fieldset->addRow($this->labels["port"], $port_widget, "port_row");

        // username textbox
        $username_widget = new TextBox("username", $values['username'], 30, 50, tt_gettext("doc.FUSION_PROXY_USERNAME"));
        $username_widget->setRequiredJavascript("String", false, 0, 50);
        $username_widget->disableIfReadOnly($this->user);

        $fieldset->addRow($this->labels["username"], $username_widget, "username_row");

        // password passwordbox
        if($values['password'])
        {
            $password = "********";
        }
        else
        {
            $password = "";
        }
        $this->form->addHiddenElement("pwd_is_changed", 0 );

        //$password_vs = $this->rest_data_adapter->generateValueSpaceObject($values['password'], tt_gettext("doc.FUSION_PROXY_PASSWORD"));
        $password_widget = new PasswordBox("password", $password, 30, 50, tt_gettext("doc.FUSION_PROXY_PASSWORD"));

        $password_widget->disableIfReadOnly($this->user);
        $password_widget->setRequiredJavascript("String", false, 0, 50);
        $password_widget->addOnKeyupHandler( "okuCheckPwdIsChanged('pwd_is_changed',this.value, '$password');");

        //$password_widget = $this->ValueSpaceWidgetFactory->getPasswordNoSaveBox( "password", $password_vs, 30, "pwd_is_changed");
        $fieldset->addRow($this->labels["password"], $password_widget, "password_row");

        $this->view->inline_javascript[] = $this->form->get_valuespace_javascript( "valuespace_validation" );
        $this->view->inline_javascript[] = $this->_get_javascript();

        $hide_shower = new FormHideShower("dataform", true);
        $hide_shower->get_show_if_watched_is_x( "enabled", array("true"), array("address_row", "port_row", "username_row", "password_row"));
        $this->view->inline_javascript[] = $hide_shower->get_main_js();
        $this->view->on_DOM_ready_javascript[] = $hide_shower->get_on_load_js();
    }

    function _get_javascript()
    {
        $js = '
        function validate(form)
        {
            if (validateIPOrHostNameWithPort(form.address, "lbl.FUSION_PROXY_ADDRESS"))
            {
                return valuespace_validation(form);
            }
            else
            {
                return false;
            }
        }';
        return $js;
    }


    // no database (just blob base) so need to validate valuespace ourself. This is just for people noodling JS
    private function updateData()
    {
        if(isset($_POST['submitbutton']))
        {
            $data = BlobLibrary::get_one($this->rest_data_adapter, $this->blob_name);
            if($data)
            {
                $verified_data = array("password" => $data['password'] );
            }
            else
            {
                $verified_data = array("password" => "" );
            }
            $bad_data = false;

            if($_POST['enabled'] === "false")
            {
                // if set to not on, don't change any other data
                if($data)
                {
                    $verified_data = $data;
                }
                $verified_data['enabled'] = "false";
            }
            else
            {
                foreach($this->regexs as $field => $regex)
                {
                    if($field === "password" && (!isset($_POST["pwd_is_changed"]) || $_POST["pwd_is_changed"] != "1"))
                    {
                        // password hasn't changed.
                        continue;
                    }
                    if(array_key_exists($field, $_POST) && preg_match($regex, $_POST[$field]))
                    {
                        $post_value = $_POST[$field];
                        if($field === "password" && $post_value != "")
                        {
                            $post_value = taa_crypto_encrypt($post_value);
                        }
                        $verified_data[$field] = $post_value;
                    }
                    else
                    {
                        if($field != "password")
                        {
                            _LOG($_POST[$field] . " didn't match " . $regex);
                        }
                        else
                        {
                            _LOG("proxy password didn't match " . $regex);
                        }
                        // should never get here as JS should catch errors
                        $this->addError(new ErrorMessage(tt_gettext("err.ERROR_TITLE"), tt_gettext("lbl.INVALID") . " " . tt_gettext($this->labels[$field])));
                        $bad_data = true;
                        break;
                    }
                }
            }
            if($bad_data)
            {
                $this->reload_from_postdata = true;
            }
            else
            {
                $post_json = json_encode($verified_data, JSON_UNESCAPED_SLASHES);
                $response = $this->rest_data_adapter->put_array(
                    array("name" => $this->blob_name, "value" => $post_json),
                    "configuration/cafe/cafeblobconfiguration/name/" . $this->blob_name);
                // raise good banner
                $this->addError($this->ErrorFactory->get("saved"));
                success_redirect();
            }
        }
    }

    function writeContent()
    {
        if ( $this->reload_from_postdata )
        {
            $this->form->overrideValueWithPostData();
        }
        $this->form->render();

        $xref = new CrossReferencePanel("RELATED TASKS");
        $xref->addEntry( "btn.REDIRECT_TO_FUSION", "fusionregistration" ); 
        $xref->render();
    }
}

$page = new FusionProxyPage();
$page->render();

?>
