import os.path
import uuid
import yaml
import logging

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)


class Config(object):
    config_dict = {}
    _exp_hostname1 = None
    _exp_hostname2 = None
    _exp_hostname3 = None
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
    _expected_connectors = None
    _cluster_name = str(uuid.uuid4())

    def __init__(self, file_names=None):
        if file_names is None:
            file_names = ["../configuration/default.yaml",
                          "tests_integration/configuration/default.yaml"]
        for config_file in file_names:
            if os.path.isfile(config_file):
                with open(config_file, 'r') as ymlfile:
                    cfg = yaml.load(ymlfile)
                    for section in cfg:
                        self.config_dict.update(cfg[section])

        self._exp_hostname1 = self.get_if_present("exp_hostname1")
        self._exp_hostname2 = self.get_if_present("exp_hostname2")
        self._exp_hostname3 = self.get_if_present("exp_hostname3")
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
        self._expected_connectors = self.get_if_present("expected_connectors")

    def get_if_present(self, item):
        if item in self.config_dict:
            return self.config_dict[item]

    def exp_hostname1(self):
        if not self._exp_hostname1:
            LOG.error("Config item (exp_hostname1) to run test was not found in config file")
            assert False
        return self._exp_hostname1

    def exp_hostname2(self):
        if not self._exp_hostname2:
            LOG.error("Config item (exp_hostname2) to run test was not found in config file")
            assert False
        return self._exp_hostname2

    def exp_hostname3(self):
        if not self._exp_hostname3:
            LOG.error("Config item (exp_hostname3) to run test was not found in config file")
            assert False
        return self._exp_hostname3

    def exp_admin_user(self):
        if not self._exp_admin_user:
            LOG.error("Config item (exp_admin_user) to run test was not found in config file")
            assert False
        return self._exp_admin_user

    def exp_admin_pass(self):
        if not self._exp_admin_pass:
            LOG.error("Config item (exp_admin_pass) to run test was not found in config file")
            assert False
        return self._exp_admin_pass

    def exp_root_user(self):
        if not self._exp_root_user:
            LOG.error("Config item (exp_root_user) to run test was not found in config file")
            assert False
        return self._exp_root_user

    def exp_root_pass(self):
        if not self._exp_root_pass:
            LOG.error("Config item (exp_root_pass) to run test was not found in config file")
            assert False
        return self._exp_root_pass

    def org_id(self):
        if not self._org_id:
            LOG.error("Config item (org_id) to run test was not found in config file")
            assert False
        return self._org_id

    def org_admin_user(self):
        if not self._org_admin_user:
            LOG.error("Config item (org_admin_user) to run test was not found in config file")
            assert False
        return self._org_admin_user

    def org_admin_password(self):
        if not self._org_admin_password:
            LOG.error("Config item (org_admin_password) to run test was not found in config file")
            assert False
        return self._org_admin_password

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

    def cluster_name(self):
        return self._cluster_name

    def expected_connectors(self):
        if not self._expected_connectors:
            LOG.error("Config item (expected_connectors) to run test was not found in config file")
            assert False
        return self._expected_connectors
