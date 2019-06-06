import os.path
import uuid

import yaml

from tests_integration.utils.integration_test_logger import get_logger

LOG = get_logger()


class Config(object):
    config_dict = {}
    _exp_hostname_primary = None
    _exp_hostname_secondary = None
    _exp_admin_user = None
    _exp_admin_pass = None
    _exp_root_user = None
    _exp_root_pass = None
    _org_id = None
    _org_admin_user = None
    _org_admin_password = None
    _client_id = None
    _client_secret = None
    _fms_server = None
    _rd_server = None
    _ci_broker_server = None
    _control_hub = None
    _expected_connectors = None
    _cluster_name = str(uuid.uuid4())

    def __init__(self):
        config_file = os.environ.get("CONFIG_FILE")
        if config_file is None:
            file_names = ["../configuration/default.yaml",
                          "../tests_integration/configuration/default.yaml",
                          "tests_integration/configuration/default.yaml"]
        else:
            file_names = [config_file]

        for config_file in file_names:
            if os.path.isfile(config_file):
                with open(config_file, 'r') as ymlfile:
                    cfg = yaml.load(ymlfile)
                    for section in cfg:
                        self.config_dict.update(cfg[section])

        self._exp_hostname_primary = self.get_if_present("exp_hostname_primary")
        self._exp_hostname_secondary = self.get_if_present("exp_hostname_secondary")
        self._exp_admin_user = self.get_if_present("exp_admin_user")
        self._exp_admin_pass = self.get_if_present("exp_admin_pass")
        self._exp_root_user = self.get_if_present("exp_root_user")
        self._exp_root_pass = self.get_if_present("exp_root_pass")
        self._org_id = self.get_if_present("org_id")
        self._org_admin_user = self.get_if_present("org_admin_user")
        self._org_admin_password = self.get_if_present("org_admin_password")
        self._client_id = self.get_if_present("client_id")
        self._client_secret = self.get_if_present("client_secret")
        self._fms_server = self.get_if_present("fms_server")
        self._rd_server = self.get_if_present("rd_server")
        self._ci_broker_server = self.get_if_present("ci_broker_server")
        self._control_hub = self.get_if_present("control_hub")
        self._expected_connectors = self.get_if_present("expected_connectors")

    def get_if_present(self, item):
        if item in self.config_dict:
            return self.config_dict[item]

    def exp_hostname_primary(self):
        hostname = os.environ.get("EXP_HOSTNAME_PRIMARY")
        if hostname:
            return hostname
        elif self._exp_hostname_primary:
            return self._exp_hostname_primary
        else:
            LOG.error("Config item (exp_hostname_primary) to run test was not found in env var nor config file")
            assert False

    def exp_hostname_secondary(self):
        hostname = os.environ.get("EXP_HOSTNAME_SECONDARY")
        if hostname:
            return hostname
        elif self._exp_hostname_secondary:
            return self._exp_hostname_secondary
        else:
            LOG.error("Config item (exp_hostname_secondary) to run test was not found in env var nor config file")
            assert False

    def exp_admin_user(self):
        user = os.environ.get("EXP_ADMIN_USER")
        if user:
            return user
        elif self._exp_admin_user:
            return self._exp_admin_user
        else:
            LOG.error("Config item (exp_admin_user) to run test was not found in config file")
            assert False

    def exp_admin_pass(self):
        password = os.environ.get("EXP_ADMIN_PASS")
        if password:
            return password
        elif self._exp_admin_pass:
            return self._exp_admin_pass
        else:
            LOG.error("Config item (exp_admin_pass) to run test was not found in config file")
            assert False

    def exp_root_user(self):
        user = os.environ.get("EXP_ROOT_USER")
        if user:
            return user
        elif self._exp_root_user:
            return self._exp_root_user
        else:
            LOG.error("Config item (exp_root_user) to run test was not found in config file")
            assert False

    def exp_root_pass(self):
        password = os.environ.get("EXP_ROOT_PASS")
        if password:
            return password
        elif self._exp_root_pass:
            return self._exp_root_pass
        else:
            LOG.error("Config item (exp_root_pass) to run test was not found in config file")
            assert False

    def org_id(self):
        org_id = os.environ.get("ORG_ID")
        if org_id:
            return org_id
        elif self._org_id:
            return self._org_id
        else:
            LOG.error("Config item (org_id) to run test was not found in config file")
            assert False

    def org_admin_user(self):
        user = os.environ.get("ORG_ADMIN_USER")
        if user:
            return user
        elif self._org_admin_user:
            return self._org_admin_user
        else:
            LOG.error("Config item (org_admin_user) to run test was not found in config file")
            assert False

    def org_admin_password(self):
        password = os.environ.get("ORG_ADMIN_PASSWORD")
        if password:
            return password
        elif self._org_admin_password:
            return self._org_admin_password
        else:
            LOG.error("Config item (org_admin_password) to run test was not found in config file")
            assert False

    def client_id(self):
        if not self._client_id:
            LOG.error("Config item (client_id) to run test was not found in config file")
            assert False
        return self._client_id

    def client_secret(self):
        if not self._client_secret:
            LOG.error("Config item (client_secret) to run test was not found in config file")
            assert False
        return self._client_secret

    def fms_server(self):
        if not self._fms_server:
            LOG.error("Config item (fms_server) to run test was not found in config file")
            assert False
        return self._fms_server

    def rd_server(self):
        if not self._rd_server:
            LOG.error("Config item (rd_server) to run test was not found in config file")
            assert False
        return self._rd_server

    def ci_broker_server(self):
        if not self._ci_broker_server:
            LOG.error("Config item (ci_broker_server) to run test was not found in config file")
            assert False
        return self._ci_broker_server

    def control_hub(self):
        if not self._control_hub:
            LOG.error("Config item (control_hub) to run test was not found in config file")
            assert False
        return self._control_hub

    def cluster_name(self):
        return self._cluster_name

    def expected_connectors(self):
        if not self._expected_connectors:
            LOG.error("Config item (expected_connectors) to run test was not found in config file")
            assert False
        return self._expected_connectors

    @staticmethod
    def expected_version():
        version = os.environ.get("EXPECTED_VERSION")
        if version:
            return version
        else:
            return None
