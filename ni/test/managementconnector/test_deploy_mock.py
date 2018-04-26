""" Deploy Test Test - http://www.toptal.com/python/an-introduction-to-mocking-in-python """

import mock
import io
import urllib2
import unittest
import logging
import sys
import ssl
import json
import random

sys.path.append("/opt/c_mgmt/bin/")
# Sys Path needs to be in place before imports performed
from ni.managementconnector.platform.libraryutils import LibraryUtils
LibraryUtils.append_library_path()

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.platform.http import Http, CertificateExceptionFusionCA
from ni.managementconnector.deploy import Deploy
from ni.managementconnector.cloud.atlas import Atlas
from ni.managementconnector.cloud.mercury import Mercury
from ni.managementconnector.config.config import Config
from ni.managementconnector.service.service import Service, DownloadTLPAccessException, DownloadServerUnavailableException, \
    EnableException, DisableException, InstallException


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()

def config_empty_read_side_effect(*args, **kwargs):
    if args[0] == ManagementConnectorProperties.INSTALL_BLACK_LIST:
        return {}

def config_blacklist_read_side_effect(*args, **kwargs):
    if args[0] == ManagementConnectorProperties.INSTALL_BLACK_LIST:
        return {"c_ucmc": {"url": "http://jebaraj-lnx.cisco.com:8080/ucmc-tlp/c_ucmc_8.6-1.0.337.tlp", "version": "8.6-1.0.337"}, 
        "c_cal": {"url": "https://sqfusion-jenkins.cisco.com/job/PIPELINE_CALCLOUD_PROMOTED/lastSuccessfulBuild/artifact/c_cal_8.6-1.0.933.tlp", "version": "8.6-1.0.933"}}

def config_read_side_effect(*args, **kwargs):
    return [{"display_name": "Calendar Connector", "name": "c_cal"}, {"display_name": "Management Connector", "name": "c_mgmt"}]


raised_alarm=None
def is_raised_side_effect(guid):
    global raised_alarm
    DEV_LOGGER.info("is_raised_side_effect: raised_alarm=" + guid)
    return raised_alarm != None

def raise_side_effect(guid, params=None):
    global raised_alarm
    DEV_LOGGER.info("raise_side_effect: raise_alarm=" + guid)
    raised_alarm = guid

def clear_alarm_side_effect(guid):
    global raised_alarm
    raised_alarm = None


class DeployTestCase(unittest.TestCase):

    @mock.patch('ni.managementconnector.deploy.ServiceUtils.get_previous_versions')
    @mock.patch('ni.managementconnector.deploy.MCAlarm')
    @mock.patch('ni.managementconnector.config.config.Config')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    def test_overlay_blacklist(self, mock_alarm, mock_config, mock_oauth, mock_previous):

        deploy = Deploy(Config())
        deploy._oauth = mock_oauth
        deploy._config = mock_config

        mock_alarm.is_raised.side_effect = is_raised_side_effect
        mock_alarm.raise_alarm.side_effect = raise_side_effect
        mock_alarm.clear_alarm.side_effect = clear_alarm_side_effect
        deploy._alarms = mock_alarm

        # 
        # empty case
        #
        connectors_config = [{'display_name': 'Calendar Service', 'name': 'c_cal', 'url': 'https://sqfusion-jenkins.cisco.com/job/PIPELINE_CALCLOUD_PROMOTED/lastSuccessfulBuild/artifact/c_cal_8.6-1.0.933.tlp', 'enabled': 'false', 'connector_type': 'c_cal', 'version': '8.6-1.0.933'}, 
             {'display_name': 'Fusion Management', 'name': 'c_mgmt', 'url': 'http://somwhere/c_mgmt_8.6-1.0.001.tlp', 'enabled': 'false', 'connector_type': 'c_mgmt', 'version': '8.6-1.0.001'}, 
             {'display_name': 'UCM Service', 'name': 'c_ucmc', 'url': 'http://jebaraj-lnx.cisco.com:8080/ucmc-tlp/c_ucmc_8.6-1.0.337.tlp', 'enabled': 'false', 'connector_type': 'c_ucmc', 'version': '8.6-1.0.337'}]

        mock_config.read.side_effect = config_empty_read_side_effect
        mock_previous.return_value = {}

        deploy._overlay_blacklist(connectors_config)

        self.assertEquals(connectors_config[2]['url'], 'http://jebaraj-lnx.cisco.com:8080/ucmc-tlp/c_ucmc_8.6-1.0.337.tlp')
        self.assertEquals(connectors_config[2]['version'], '8.6-1.0.337')
        self.assertFalse(mock_alarm.is_raised("a2a259b5-93a6-4a1a-b03d-36ac0987e6db"))


        # 
        # cal and ucm black listed
        #
        connectors_config = [{'display_name': 'Calendar Service', 'name': 'c_cal', 'url': 'https://sqfusion-jenkins.cisco.com/job/PIPELINE_CALCLOUD_PROMOTED/lastSuccessfulBuild/artifact/c_cal_8.6-1.0.933.tlp', 'enabled': 'false', 'connector_type': 'c_cal', 'version': '8.6-1.0.933'}, 
             {'display_name': 'Fusion Management', 'name': 'c_mgmt', 'url': 'http://somwhere/c_mgmt_8.6-1.0.001.tlp', 'enabled': 'false', 'connector_type': 'c_mgmt', 'version': '8.6-1.0.001'}, 
             {'display_name': 'UCM Service', 'name': 'c_ucmc', 'url': 'http://jebaraj-lnx.cisco.com:8080/ucmc-tlp/c_ucmc_8.6-1.0.337.tlp', 'enabled': 'false', 'connector_type': 'c_ucmc', 'version': '8.6-1.0.337'}]

        mock_config.read.side_effect = config_blacklist_read_side_effect
        mock_previous.return_value = {"c_ucmc": {"url": "http://jebaraj-lnx.cisco.com:8080/ucmc-tlp/c_ucmc_8.6-1.0.300.tlp", "version": "8.6-1.0.300"},
        "c_cal": {"url": "https://sqfusion-jenkins.cisco.com/job/PIPELINE_CALCLOUD_PROMOTED/lastSuccessfulBuild/artifact/c_cal_8.6-1.0.900.tlp", "version": "8.6-1.0.900"}}

        deploy._overlay_blacklist(connectors_config)

        self.assertEquals(connectors_config[2]['url'], 'http://jebaraj-lnx.cisco.com:8080/ucmc-tlp/c_ucmc_8.6-1.0.300.tlp')
        self.assertEquals(connectors_config[2]['version'], '8.6-1.0.300')
        self.assertEquals(connectors_config[0]['url'], 'https://sqfusion-jenkins.cisco.com/job/PIPELINE_CALCLOUD_PROMOTED/lastSuccessfulBuild/artifact/c_cal_8.6-1.0.900.tlp')
        self.assertEquals(connectors_config[0]['version'], '8.6-1.0.900')
        self.assertTrue(mock_alarm.is_raised("a2a259b5-93a6-4a1a-b03d-36ac0987e6db"))

        # 
        # empty case again (want to ensure alarm is lowered)
        #
        connectors_config = [{'display_name': 'Calendar Service', 'name': 'c_cal', 'url': 'https://sqfusion-jenkins.cisco.com/job/PIPELINE_CALCLOUD_PROMOTED/lastSuccessfulBuild/artifact/c_cal_8.6-1.0.933.tlp', 'enabled': 'false', 'connector_type': 'c_cal', 'version': '8.6-1.0.933'}, 
             {'display_name': 'Fusion Management', 'name': 'c_mgmt', 'url': 'http://somwhere/c_mgmt_8.6-1.0.001.tlp', 'enabled': 'false', 'connector_type': 'c_mgmt', 'version': '8.6-1.0.001'}, 
             {'display_name': 'UCM Service', 'name': 'c_ucmc', 'url': 'http://jebaraj-lnx.cisco.com:8080/ucmc-tlp/c_ucmc_8.6-1.0.337.tlp', 'enabled': 'false', 'connector_type': 'c_ucmc', 'version': '8.6-1.0.337'}]

        mock_config.read.side_effect = config_empty_read_side_effect
        mock_previous.return_value = {}

        deploy._overlay_blacklist(connectors_config)

        self.assertEquals(connectors_config[2]['url'], 'http://jebaraj-lnx.cisco.com:8080/ucmc-tlp/c_ucmc_8.6-1.0.337.tlp')
        self.assertEquals(connectors_config[2]['version'], '8.6-1.0.337')
        self.assertFalse(mock_alarm.is_raised("a2a259b5-93a6-4a1a-b03d-36ac0987e6db"))

    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.is_package_installed")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch('ni.managementconnector.config.config')
    @mock.patch('ni.managementconnector.deploy.OAuth')
    @mock.patch('ni.managementconnector.service.servicemanager.MCAlarm')
    @mock.patch('ni.managementconnector.deploy.ServiceUtils')
    @mock.patch('ni.managementconnector.service.service.ServiceUtils')
    def test_tlp_download_alarm(self, mock_service_utils, mock_deploy_utils, mock_alarm, mock_oauth, mock_config, mock_get_package_version, mock_get_system_mem, mock_is_package_installed):

        DEV_LOGGER.info("***TEST*** test_tlp_raised_alarm")


        deploy = Deploy(mock_config)
        deploy._service_manager.purge_deleted_connectors = mock.MagicMock(name='method')
        deploy._service_manager._alarms = mock_alarm
        
        mock_service_name = "mock_service"

        service = Service(mock_service_name, mock_config, mock_oauth)
        mocked_download_method =  mock.Mock(side_effect=DownloadTLPAccessException({"message":"problem accessing tlp", "reason": "reason"}))
        service._download = mocked_download_method

        deploy._service_manager.add(service)

        connectors_config = []
        connectors_config.append({'connector_type': mock_service_name,
                            'version': "version",
                            'display_name' : 'xyz_display_name',
                            'name': mock_service_name, 'url': 'http://www.bad_address.com', 'enabled': 'false'
                            })


        deploy._service_manager.upgrade_worker(connectors_config)

        description_text = ['Could not download connector xyz_display_name from http://www.bad_address.com\n']
        mock_alarm.raise_alarm.assert_called_with('3d541e1e-1e9c-4b30-a07d-e93f8445b13e', mock.ANY)

    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.is_package_installed")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch('ni.managementconnector.config.config')
    @mock.patch('ni.managementconnector.deploy.OAuth')
    @mock.patch('ni.managementconnector.service.servicemanager.MCAlarm')
    @mock.patch('ni.managementconnector.deploy.ServiceUtils')
    @mock.patch('ni.managementconnector.service.service.ServiceUtils')
    def test_install_alarm(self, mock_service_utils, mock_deploy_utils, mock_alarm, mock_oauth, mock_config, mock_get_package_version, mock_get_system_mem, mock_is_package_installed):

        DEV_LOGGER.info("***TEST*** test_install_alarm")

        deploy = Deploy(mock_config)
        deploy._service_manager.purge_deleted_connectors = mock.MagicMock(name='method')
        deploy._service_manager._alarms = mock_alarm

        mock_service_name = "mock_service"

        service = Service(mock_service_name, mock_config, mock_oauth)
        mocked_install_method = mock.Mock(side_effect=InstallException({"message": "IOError"}))
        service._install = mocked_install_method

        service._download = mock.MagicMock(name='method')
        service._download.return_value = "mock_path", "fileSize", "downloadDuration"

        deploy._service_manager.add(service)

        connectors_config = []
        connectors_config.append({'connector_type': mock_service_name,
                            'version': "version",
                            'display_name' : 'xyz_display_name',
                            'name': mock_service_name, 'url': 'http://www.bad_address.com', 'enabled': 'false'
                            })


        deploy._service_manager.upgrade_worker(connectors_config)

        description_text = ['Could not install connector xyz_display_name (version), downloaded from http://www.bad_address.com\n']
        mock_alarm.raise_alarm.assert_called_with('76a2fbce-97bb-4761-9fab-8ffd4b0ab9a2', mock.ANY)

    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.is_package_installed")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch('ni.managementconnector.config.config')
    @mock.patch('ni.managementconnector.deploy.OAuth')
    @mock.patch('ni.managementconnector.service.servicemanager.MCAlarm')
    @mock.patch('ni.managementconnector.deploy.ServiceUtils')
    @mock.patch('ni.managementconnector.service.service.ServiceUtils')

    def test_download_server_unavailable_alarm(self, mock_service_utils, mock_deploy_utils, mock_alarm, mock_oauth, mock_config, mock_get_package_version, mock_get_system_mem, mock_is_package_installed):

        DEV_LOGGER.info("***TEST*** test_download_server_unavailable_alarm")

        deploy = Deploy(mock_config)
        deploy._service_manager.purge_deleted_connectors = mock.MagicMock(name='method')
        deploy._service_manager._alarms = mock_alarm

        mock_service_name = "mock_service"

        service = Service(mock_service_name, mock_config, mock_oauth)
        mocked_download_method =  mock.Mock(side_effect=DownloadServerUnavailableException({"message":"problem accessing tlp", "reason": "reason"}))

        service._download = mocked_download_method

        deploy._service_manager.add(service)

        connectors_config = []
        connectors_config.append({'connector_type': mock_service_name,
                            'version': "version",
                            'display_name' : 'xyz_display_name',
                            'name': mock_service_name, 'url': 'http://www.bad_address.com', 'enabled': 'false'
                            })


        deploy._service_manager.upgrade_worker(connectors_config)

        description_text = ['Could not connect to www.bad_address.com to download connector xyz_display_name\n']
        mock_alarm.raise_alarm.assert_called_with('b6417be9-0c57-4254-8392-896b61983ca4', mock.ANY)


    @mock.patch('ni.managementconnector.service.servicemanager.MCAlarm')
    def test_process_unknownhost_alarm(self, mock_alarm):

        deploy = Deploy(Config())
        deploy._service_manager._alarms = mock_alarm

        failed_config = []
        alarm_id = 'id'
        alarm_msg = 'url %s, name %s'

        deploy._service_manager._process_unknownhost_alarm(failed_config, alarm_id, alarm_msg)

        mock_alarm.clear_alarm.assert_called_with(alarm_id)

        failed_config.append({'display_name' : 'xyz_display_name', 'url': 'http://www.dsdsadsaudvs_bad_address.com'})

        deploy._service_manager._process_unknownhost_alarm(failed_config, alarm_id, alarm_msg)

        description_text = ['url www.dsdsadsaudvs_bad_address.com, name xyz_display_name\n']

        mock_alarm.raise_alarm.assert_called_with(alarm_id, description_text)


    @mock.patch('ni.managementconnector.service.servicemanager.MCAlarm')
    def test_process_upgrade_alarm(self, mock_alarm):

        deploy = Deploy(Config())
        deploy._service_manager._alarms = mock_alarm

        failed_config = []
        alarm_id = 'id'
        alarm_msg = 'url %s, name %s'

        deploy._service_manager._process_upgrade_alarm(failed_config, alarm_id, alarm_msg)

        mock_alarm.clear_alarm.assert_called_with(alarm_id)

        failed_config.append({'display_name' : 'xyz_display_name', 'url': 'http://www.dsdsadsaudvs_bad_address.com'})

        deploy._service_manager._process_upgrade_alarm(failed_config, alarm_id, alarm_msg)

        description_text = ['url xyz_display_name, name http://www.dsdsadsaudvs_bad_address.com\n']

        mock_alarm.raise_alarm.assert_called_with(alarm_id, description_text)


    @mock.patch('ni.managementconnector.deploy.time.sleep')
    @mock.patch('ni.managementconnector.service.servicemanager.CafeXUtils')
    @mock.patch('ni.managementconnector.service.servicemanager.ServiceManager.purge')
    def test_purge_deleted_connectors(self, mock_purge, mock_cafexutils, mock_sleep):

        deploy = Deploy(Config())

        #Nothing to Purge
        mock_cafexutils.get_installed_connectors.return_value = ['c_xyz']
        connectors_config = []

        connectors_config.append({'connector_type': "c_xyz",
                            'version': "version",
                            'display_name' : 'xyz_display_name',
                            'name': "c_xyz", 'url': 'http://www.dsdsadsaudvs_bad_address.com', 'enabled': 'false'
                            })

        deploy._service_manager.purge_deleted_connectors(connectors_config, "c_")

        self.assertFalse(mock_purge.called, "Purge should not have been called.")

        #c_abc should be Purged, its installed but not in list of connectors

        mock_cafexutils.get_installed_connectors.return_value = ['c_abc']

        connectors_config = []

        connectors_config.append({'connector_type': "c_xyz",
                            'version': "version",
                            'display_name' : 'xyz_display_name',
                            'name': "c_xyz", 'url': 'http://www.dsdsadsaudvs_bad_address.com', 'enabled': 'false'
                            })

        deploy._service_manager.purge_deleted_connectors(connectors_config, "c_")

        mock_purge.assert_called_with('c_abc', False)


    def test_entitled_services_changed(self):
        """ Test Deploy Started """

        self.assertFalse(Deploy.entitled_services_changed([{"name":"csi", "display_name" : "Cal"}],
                                                                       [{"name":"csi", "display_name" : "Cal"}]))

        self.assertTrue(Deploy.entitled_services_changed([{"name":"c", "display_name" : "Test"},
                                                                        {"name":"csi", "display_name" : "Cal"}],
                                                                       [{"name":"csi", "display_name" : "Cal"}]))

        self.assertTrue(Deploy.entitled_services_changed([{"name":"c", "display_name" : "Test"},
                                                                        {"name":"csi", "display_name" : "Cal"}],
                                                                       []))

        self.assertTrue(Deploy.entitled_services_changed([], [{"name":"c", "display_name" : "Test"},
                                                                        {"name":"csi", "display_name" : "Cal"}]))

        self.assertFalse(Deploy.entitled_services_changed([], []))


        self.assertFalse(Deploy.entitled_services_changed([{"name":"c", "display_name" : "Test"},
                                                                        {"name":"csi", "display_name" : "Cal"}],
                                                                       [{"name":"csi", "display_name" : "Cal"},
                                                                        {"name":"c", "display_name" : "Test"}]))

        # Test entitled services are updated when the display name changes
        self.assertTrue(Deploy.entitled_services_changed([{"name":"c", "display_name" : "Test Different Name"}],
                                                                       [{"name":"c", "display_name" : "Test"}]))
                                                                       
        self.assertTrue(Deploy.entitled_services_changed([{"name":"c", "display_name" : "Test Different Name"},
                                                                        {"name":"csi", "display_name" : "Cal"}],
                                                                       [{"name":"csi", "display_name" : "Cal"},
                                                                        {"name":"c", "display_name" : "Test"}]))

        self.assertTrue(Deploy.entitled_services_changed([{"name":"c", "display_name" : "Test Different Name"},
                                                                        {"name":"csi", "display_name" : "Cal"}],
                                                                       [{"name":"c", "display_name" : "Test"}]))



    @mock.patch('ni.managementconnector.deploy.CafeXUtils')
    @mock.patch('ni.managementconnector.service.service.Service')
    @mock.patch('ni.managementconnector.deploy.MCAlarm')
    @mock.patch('ni.managementconnector.config.config.Config')
    @mock.patch('ni.managementconnector.service.servicemanager.ServiceManager')
    def test_noop_config_baseline(self, mock_servicemanager, mock_config, mock_alarm, mock_service, mock_cafexutils):
        ''' FMS at times may send an empty package in heartbeat
            this will indicate to FMC not to attempt package upgrade/remove'''
  
        # Case 1
        # baseline test
        # ensure config with tlp urls passes positive tests

        deploy = Deploy(Config())
        deploy._alarms = mock_alarm
        deploy._config = mock_config

        deploy._service_manager = mock_servicemanager
        mock_cafexutils.get_installed_connectors.return_value = ['c_mgmt', 'c_cal', 'c_ucc', 'd_java']
        mock_config.read.side_effect = config_read_side_effect
        mock_service.configure.side_effect = None

        mc_typical_provisioning = { 
            "connectors" : [
              {'connector_type': 'c_mgmt', 'display_name': 'Management Connector', 'version': '8.6-1.0.318968', 'packages': [{'tlp_url': 'https://foo/c_mgmt.tlp'}]}, 
              {'connector_type': 'c_cal', 'display_name': 'Calendar Connector', 'version': '8.6-1.0.318000', 'packages': [{'tlp_url': 'https://foo/c_cal.tlp'}]}, 
              {'connector_type': 'c_ucc', 'display_name': 'UC Connector', 'version': '8.6-1.0.318000', 'packages': [{'tlp_url': 'https://foo/c_ucc.tlp'}]} 
                            ],
            "dependencies" : [
              {'dependencyType': 'd_java', 'display_name': 'Java', 'version': '8.6-1.0.318968', 'tlpUrl': 'https://foo/d_java.tlp'}
                            ]
            }


        config_return = deploy._get_config(mc_typical_provisioning)
        # sample config return
        # [{'url': 'https://foo/d_java.tlp', 'dependency': 'true', 'version': '8.6-1.0.318968', 'display_name': 'd_java', 'name': 'd_java'}, 
        # {'display_name': 'Management Connector', 'name': 'c_mgmt', 'url': 'https://foo/c_mgmt.tlp', 'enabled': 'false', 'connector_type': 'c_mgmt', 'version': '8.6-1.0.318968'}, 
        # {'display_name': 'Calendar Connector', 'name': 'c_cal', 'url': 'https://foo/c_cal.tlp', 'enabled': 'false', 'connector_type': 'c_cal', 'version': '8.6-1.0.318000'}, 
        # {'display_name': 'UC Connector', 'name': 'c_ucc', 'url': 'https://foo/c_ucc.tlp', 'enabled': 'false', 'connector_type': 'c_ucc', 'version': '8.6-1.0.318000'}]

        DEV_LOGGER.info("***TEST*** test_noop_config: base case: config_return:%s" % config_return)
        self.assertEqual(4, len(config_return))
        # don't want tests to be dependenct on order
        i=-1
        indices = {}
        for config in config_return:
            i = i+1
            if config['name'] == 'd_java':
                indices['d_java'] = i
            elif config['name'] == 'c_mgmt':
                indices['c_mgmt'] = i
            elif config['name'] == 'c_cal':
                indices['c_cal'] = i
            elif config['name'] == 'c_ucc':
                indices['c_ucc'] = i


        self.assertEqual('d_java', config_return[indices['d_java']]['name'])
        self.assertEqual('c_mgmt', config_return[indices['c_mgmt']]['name'])
        self.assertEqual('c_cal', config_return[indices['c_cal']]['name'])
        self.assertEqual('c_ucc', config_return[indices['c_ucc']]['name'])

        self.assertEqual(True, config_return[indices['d_java']]['allow_upgrade'])
        self.assertEqual(True, config_return[indices['c_mgmt']]['allow_upgrade'])
        self.assertEqual(True, config_return[indices['c_cal']]['allow_upgrade'])
        self.assertEqual(True, config_return[indices['c_ucc']]['allow_upgrade'])
       

    @mock.patch('ni.managementconnector.deploy.CafeXUtils')
    @mock.patch('ni.managementconnector.service.service.Service')
    @mock.patch('ni.managementconnector.deploy.MCAlarm')
    @mock.patch('ni.managementconnector.config.config.Config')
    @mock.patch('ni.managementconnector.service.servicemanager.ServiceManager')
    def test_noop_config_empty_tlps(self, mock_servicemanager, mock_config, mock_alarm, mock_service, mock_cafexutils):
        ''' FMS at times may send an empty package in heartbeat
            this will indicate to FMC not to attempt package upgrade/remove'''
  
        # Case 2
        # noop test
        # ensure empty tlps config does not attempt to update

        deploy = Deploy(Config())
        deploy._alarms = mock_alarm
        deploy._config = mock_config

        deploy._service_manager = mock_servicemanager
        mock_cafexutils.get_installed_connectors.return_value = ['c_mgmt', 'c_cal', 'c_ucc', 'd_java']
        mock_config.read.side_effect = config_read_side_effect
        mock_service.configure.side_effect = None


        mc_empty_provisioning = { 
            "connectors" : [
              {'connector_type': 'c_mgmt', 'display_name': 'Management Connector', 'version': '8.6-1.0.318968', 'packages': []}, 
              {'connector_type': 'c_cal', 'display_name': 'Calendar Connector', 'version': '8.6-1.0.318000', 'packages': []}, 
              {'connector_type': 'c_ucc', 'display_name': 'UC Connector', 'version': '8.6-1.0.318000', 'packages': []} 
                            ],
            "dependencies" : [
              {'dependencyType': 'd_java', 'display_name': 'Java', 'version': '8.6-1.0.318968', 'tlpUrl': ''}
                            ]
            }

        config_return = deploy._get_config(mc_empty_provisioning)
        DEV_LOGGER.info("***TEST*** test_noop_config: noop case: config_return:%s" % config_return)

        self.assertEqual(4, len(config_return))
        i=-1
        indices = {}
        for config in config_return:
            i = i+1
            if config['name'] == 'd_java':
                indices['d_java'] = i
            elif config['name'] == 'c_mgmt':
                indices['c_mgmt'] = i
            elif config['name'] == 'c_cal':
                indices['c_cal'] = i
            elif config['name'] == 'c_ucc':
                indices['c_ucc'] = i


        self.assertEqual('d_java', config_return[indices['d_java']]['name'])
        self.assertEqual('c_mgmt', config_return[indices['c_mgmt']]['name'])
        self.assertEqual('c_cal', config_return[indices['c_cal']]['name'])
        self.assertEqual('c_ucc', config_return[indices['c_ucc']]['name'])

        self.assertEqual(False, config_return[indices['d_java']]['allow_upgrade'])
        self.assertEqual(False, config_return[indices['c_mgmt']]['allow_upgrade'])
        self.assertEqual(False, config_return[indices['c_cal']]['allow_upgrade'])
        self.assertEqual(False, config_return[indices['c_ucc']]['allow_upgrade'])

    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch('ni.managementconnector.service.eventdampener.EventDampener')
    @mock.patch('ni.managementconnector.service.servicemanager.EventSender.post')
    @mock.patch('ni.managementconnector.service.service.Service.configure',
                side_effect=DisableException({"message": "Could not disable service", "name": "name",
                                              "version": "version"}))
    @mock.patch('ni.managementconnector.service.servicemanager.MCAlarm')
    @mock.patch('ni.managementconnector.service.servicemanager.CafeXUtils')
    def test_disable_exception(self, mock_utils, mock_alarm, mock_service, mock_sender, mock_dampener, mock_get_package_version, mock_get_system_mem):
        mock_dampener.reset_counters()

        deploy = Deploy(Config())
        deploy._service_manager._alarms = mock_alarm

        mock_utils.get_installed_connectors.return_value = []

        connectors_config = [{'connector_type': "c_xyz",
                              'version': "version",
                              'display_name': 'xyz',
                              'name': "c_xyz", 'url': 'http://www.dsdsadsaudvs_bad_address.com', 'enabled': 'false'
                              }]

        deploy._service_manager.upgrade_worker(connectors_config)

        description_text = ['Could not disable the xyz connector\n']
        mock_alarm.raise_alarm.assert_called_with('77857c20-94b4-4145-8298-cad741e905fb', mock.ANY)
        mock_sender.assert_called()
        mock_dampener.reset_counters()

    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch('ni.managementconnector.service.eventdampener.EventDampener')
    @mock.patch('ni.managementconnector.service.servicemanager.ManagementConnectorProperties.EXPRESSWAY_FULL_VERSION')
    @mock.patch('ni.managementconnector.service.servicemanager.time')
    @mock.patch('ni.managementconnector.deploy.OAuth')
    @mock.patch('ni.managementconnector.service.servicemanager.EventSender.post')
    @mock.patch('ni.managementconnector.service.service.Service.configure',
                side_effect=EnableException({"message": "Could not disable service", "name": "name",
                                             "version": "version"}))
    @mock.patch('ni.managementconnector.service.servicemanager.MCAlarm')
    @mock.patch('ni.managementconnector.service.servicemanager.CafeXUtils')
    def test_enable_exception(self, mock_utils, mock_alarm, mock_service, mock_sender, mock_oauth, mock_time,
                              mock_platform, mock_dampener, mock_get_package_version, mock_get_system_mem):
        mock_dampener.reset_counters()

        config = Config()

        deploy = Deploy(config)
        deploy._service_manager._alarms = mock_alarm
        deploy._service_manager._oauth = mock_oauth

        mock_utils.get_installed_connectors.return_value = []

        connectors_config = []

        bad_url = 'http://www.dsdsadsaudvs_bad_address.com'

        connectors_config.append({'connector_type': "c_xyz",
                                  'version': "version",
                                  'display_name' : 'xyz',
                                  'name': "c_xyz", 'url': bad_url, 'enabled': 'false'
                                  })

        deploy._service_manager.upgrade_worker(connectors_config)

        description_text = ['Could not enable the xyz connector\n']
        mock_alarm.raise_alarm.assert_called_with('77ad9990-4850-4191-9bc2-51d0912daef3', mock.ANY)

        details = {"fields": {"url": bad_url, "platformVersion": mock_platform, "connectorVersion": "version",
                              "exception": "{'message': 'Could not disable service', 'version': 'version', "
                                           "'name': 'name'}"}, "measurementName": 'connectorUpgradeEvent',
                   "tags": {"state": 'failure', "connectorType": "c_xyz", "reason": "enable"}}

        mock_sender.assert_called_once_with(mock_oauth, config, "connectorUpgrade", "c_mgmt", 1, details)
        mock_dampener.reset_counters()

    @mock.patch('ni.managementconnector.service.service.Service.get_install_details')
    @mock.patch('ni.managementconnector.deploy.System')
    @mock.patch('ni.managementconnector.deploy.Atlas')
    @mock.patch('ni.managementconnector.deploy.OAuth')
    @mock.patch('ni.managementconnector.service.servicemanager.ServiceManager')
    @mock.patch('ni.managementconnector.service.servicemanager.MCAlarm')
    @mock.patch('ni.managementconnector.config.config')
    def test_process_version_alarm(self, mock_config, mock_alarm, mock_manager, mock_oauth, mock_atlas, mock_sys, mock_get_installed):
        """
        User Story: US7739 raise alarm if version installed is different than version advertised by FMS

        Note: Verify the version alarm gets processed correctly
        """

        DEV_LOGGER.info("***TEST*** test_process_version_alarm")
        deploy = Deploy(mock_config)
        deploy._service_manager._alarms = mock_alarm
        DEV_LOGGER.info("***TEST*** Set up mock return values")

        connectors_config = list()

        connectors_config.append({'connector_type': "c_xyz",
                                  'version': "8.6.1.0",
                                  'installed_version': "8.6.1.1",
                                  'display_name': 'xyz',
                                  'name': "c_xyz",
                                  'url': 'http://www.cdn.ciscoo.com/c_xyz_8.6.1.0.tlp',
                                  'enabled': 'false'
                            })

        DEV_LOGGER.info("***TEST*** Calling _process_version_alarm to raise alarm")
        deploy._service_manager._process_version_alarm(connectors_config, "52299415-2719-45d5-bcf7-720b48929ae3", "err.VERSION_MISMATCH_%s_%s_%s")

        description_text = ['Cisco Collaboration Cloud is advertising xyz version 8.6.1.0 but the package version is 8.6.1.1. The version numbers should be identical.\n']
        mock_alarm.raise_alarm.assert_called_with('52299415-2719-45d5-bcf7-720b48929ae3', mock.ANY)

        DEV_LOGGER.info("***TEST*** Calling _process_version_alarm to lower alarm")
        connectors_config.pop()
        deploy._service_manager._process_version_alarm(connectors_config, "52299415-2719-45d5-bcf7-720b48929ae3", "err.VERSION_MISMATCH_%s_%s_%s")
        mock_alarm.clear_alarm.assert_called_with('52299415-2719-45d5-bcf7-720b48929ae3')

    @mock.patch("ni.managementconnector.platform.system.System.get_system_cpu")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch('ni.managementconnector.deploy.CrashMonitor')
    @mock.patch('ni.managementconnector.cloud.atlas.jsonhandler.write_json_file')
    @mock.patch('ni.managementconnector.deploy.Metrics')
    @mock.patch('ni.managementconnector.config.config')
    @mock.patch('ni.managementconnector.deploy.MCAlarm')
    @mock.patch('ni.managementconnector.deploy.OAuth')
    @mock.patch('ni.managementconnector.deploy.ServiceManager')
    @mock.patch('ni.managementconnector.deploy.ServiceUtils')
    @mock.patch('ni.managementconnector.cloud.atlas.Http')
    def test_ssl_error_alarm(self, mock_http, mock_utils, mock_mgr, mock_oauth, mock_alarm, mock_config, mock_metrics, mock_json_write, mock_monitor, mock_get_system_mem, mock_get_system_cpu):
        """
        User Story: US7825 - Add alarm for network timeout issues
        DE3144 - TLS alarm is misleading when we get a "...read operation timed out" from urllib2.urlopen

        Note: Verify SSL error handling along with new timeout handling for DE3144
        """

        DEV_LOGGER.info("***TEST*** test_ssl_error_alarm")

        seconds = 30

        atlas = Atlas(mock_config)
        atlas._get_post_request_data = mock.MagicMock(name='method')
        atlas._get_post_request_data.return_value = {}

        mock_mgr.get.return_value = "Mock Service"

        def config_read(path, rel_path=''):
            """ config class mock """
            DEV_LOGGER.debug("ConfigMock: read path %s" % path)

            if path == ManagementConnectorProperties.POLL_TIME:
                return seconds
            elif path == ManagementConnectorProperties.ENTITLED_SERVICES:
                return []
            else:
                DEV_LOGGER.debug("ConfigMock: Unexpected path passed: %s" % path)
                return "Mock Value"

        mock_config.read.side_effect = config_read

        mock_http.error_url = "cafe-test.cisco.com"

        # Test for non-timeout SSL error
        error = ssl.SSLError()
        error.message = "Test SSL error"

        mock_http.post.side_effect = error

        # Run Test - Generic SSL error flow
        deploy = Deploy(mock_config)
        deploy._atlas = atlas

        deploy._alarms = mock_alarm

        deploy._oauth_init = True
        deploy._do_register_config_status("test_connector")

        mock_alarm.raise_alarm.assert_called_with('233f0c18-9c8f-41ba-8800-93937540afe8', [mock_http.error_url, seconds])
        mock_alarm.reset_mock()

        mock_http.post.side_effect = None

        # Run Test - Clear Alarm
        # Switch of Upgrade - Not Interested
        deploy._is_upgrade_allowed = mock.MagicMock(name='method')
        deploy._is_upgrade_allowed.return_value = False

        deploy._do_register_config_status("test_connector")

        mock_alarm.clear_alarm.assert_any_call('233f0c18-9c8f-41ba-8800-93937540afe8')
        mock_alarm.reset_mock()

        # Run Test - Timeout error flow
        error.message = "The read operation timed out"

        mock_http.post.side_effect = error

        deploy._registration_time_out_counter = 0
        i = 0

        # Check that timeout counter is incremented with every error
        while i < ManagementConnectorProperties.REGISTRATION_TIME_OUT_LIMIT:
            deploy._do_register_config_status("test_connector")
            i = i + 1
            self.assertEqual(i, deploy._registration_time_out_counter)

        # Check that alarm is raised after timeout limit is reached
        deploy._do_register_config_status("test_connector")

        mock_alarm.raise_alarm.assert_called_with('233f0c18-9c8f-41ba-8800-93937540afe8', [mock_http.error_url, seconds])
        mock_alarm.reset_mock()

        mock_http.post.side_effect = None

    @mock.patch("ni.managementconnector.platform.system.System.get_system_cpu")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch('ni.managementconnector.cloud.atlas.jsonhandler.write_json_file')
    @mock.patch('ni.managementconnector.deploy.Metrics')
    @mock.patch('ni.managementconnector.config.config')
    @mock.patch('ni.managementconnector.deploy.MCAlarm')
    @mock.patch('ni.managementconnector.deploy.OAuth')
    @mock.patch('ni.managementconnector.deploy.ServiceManager')
    @mock.patch('ni.managementconnector.deploy.ServiceUtils')
    @mock.patch('ni.managementconnector.cloud.atlas.Http')

    def test_urllib_alarm(self, mock_http, mock_utils, mock_mgr, mock_oauth, mock_alarm, mock_config, mock_metrics, mock_json_write, mock_get_system_mem, mock_get_system_cpu):

        DEV_LOGGER.info("***TEST*** test_urllib_alarm")

        # Setup Mock Objects

        atlas = Atlas(mock_config)
        atlas._get_post_request_data = mock.MagicMock(name='method')
        atlas._get_post_request_data.return_value = {}

        mock_mgr.get.return_value = "Mock Service"

        mock_http.post.side_effect = urllib2.URLError("URL Exception")
        mock_url = "cafe-test.cisco.com"
        Http.error_url = mock_url

        # Run Test
        deploy = Deploy(mock_config)
        deploy._atlas = atlas
        deploy._alarms = mock_alarm

        deploy._oauth_init = True
        deploy._do_register_config_status("test_connector")

        mock_alarm.raise_alarm.assert_called_with('ba883968-4b5a-4f83-9e71-50c7d7621b44', [mock_url])
        mock_alarm.reset_mock()

        mock_http.post.side_effect = None

        # Run Test - Clear Alarm
        #Switch of Upgrade - Not Interested
        deploy._is_upgrade_allowed = mock.MagicMock(name='method')
        deploy._is_upgrade_allowed.return_value = False

        deploy._do_register_config_status("test_connector")

        mock_alarm.clear_alarm.assert_any_call('ba883968-4b5a-4f83-9e71-50c7d7621b44')

    @mock.patch("ni.managementconnector.platform.system.System.am_i_master")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_cpu")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch('ni.managementconnector.cloud.atlas.jsonhandler.write_json_file')
    @mock.patch('ni.managementconnector.deploy.Metrics')
    @mock.patch('ni.managementconnector.config.config')
    @mock.patch('ni.managementconnector.deploy.MCAlarm')
    @mock.patch('ni.managementconnector.deploy.OAuth')
    @mock.patch('ni.managementconnector.deploy.ServiceManager')
    @mock.patch('ni.managementconnector.deploy.ServiceUtils')
    @mock.patch('ni.managementconnector.cloud.atlas.Http')

    def test_http_alarm(self,  mock_http, mock_utils, mock_mgr, mock_oauth, mock_alarm, mock_config, mock_metrics, mock_json_write, mock_get_system_mem, mock_get_system_cpu, mock_am_i_master):

        DEV_LOGGER.info("***TEST*** test_http_alarm")

        # Setup Mock Objects

        atlas = Atlas(mock_config)
        atlas._get_post_request_data = mock.MagicMock(name='method')
        atlas._get_post_request_data.return_value = {}

        mock_mgr.get.return_value = "Mock Service"

        stream = io.TextIOWrapper(io.BytesIO(''))

        mock_http.post.side_effect = urllib2.HTTPError('http://cafe-test.cisco.com', "404", "", "hdrs", stream)
        mock_url = "cafe-test.cisco.com"
        Http.error_url = mock_url

        # Run Test - Raise Alarm
        deploy = Deploy(mock_config)
        deploy._atlas = atlas

        deploy._alarms = mock_alarm

        deploy._oauth_init = True
        deploy._do_register_config_status("test_connector")

        mock_alarm.raise_alarm.assert_called_with('cbbf0813-09cb-4e23-9182-f3996d24cc9e', ['404', "http://" + mock_url])
        mock_alarm.reset_mock()
        mock_http.post.side_effect = None

        # Run Test - Clear Alarm
        #Switch of Upgrade - Not Interested
        deploy._is_upgrade_allowed = mock.MagicMock(name='method')
        deploy._is_upgrade_allowed.return_value = False

        deploy._do_register_config_status("test_connector")

        mock_alarm.clear_alarm.assert_any_call('cbbf0813-09cb-4e23-9182-f3996d24cc9e')

    @mock.patch("ni.managementconnector.platform.system.System.get_system_cpu")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch('ni.managementconnector.cloud.atlas.jsonhandler.write_json_file')
    @mock.patch('ni.managementconnector.deploy.Metrics')
    @mock.patch('ni.managementconnector.config.config')
    @mock.patch('ni.managementconnector.deploy.MCAlarm')
    @mock.patch('ni.managementconnector.deploy.OAuth')
    @mock.patch('ni.managementconnector.deploy.ServiceManager')
    @mock.patch('ni.managementconnector.deploy.ServiceUtils')
    @mock.patch('ni.managementconnector.cloud.atlas.Http')
    def test_certificate_alarm(self, mock_http, mock_utils, mock_mgr, mock_oauth, mock_alarm, mock_config, mock_metrics, mock_json_write, mock_get_system_mem, mock_get_system_cpu):

        DEV_LOGGER.info("***TEST*** test_certificate_alarm")

        # Setup Mock Objects

        atlas = Atlas(mock_config)
        atlas._get_post_request_data = mock.MagicMock(name='method')
        atlas._get_post_request_data.return_value = {}

        mock_mgr.get.return_value = "Mock Service"

        mock_url = "cafe-test.cisco.com"
        Http.error_url = mock_url
        mock_http.post.side_effect = CertificateExceptionFusionCA("")

         # Run Test
        deploy = Deploy(mock_config)
        deploy._atlas = atlas

        deploy._alarms = mock_alarm

        deploy._oauth_init = True
        deploy._do_register_config_status("test_connector")

        mock_alarm.raise_alarm.assert_called_with('635afce6-0ae8-4b84-90f5-837a2234002b', ['cafe-test.cisco.com'])
        mock_alarm.reset_mock()

        mock_http.post.side_effect = None

        # Run Test - Clear Alarm
        #Switch of Upgrade - Not Interested
        deploy._is_upgrade_allowed = mock.MagicMock(name='method')
        deploy._is_upgrade_allowed.return_value = False

        deploy._do_register_config_status("test_connector")

        mock_alarm.clear_alarm.assert_any_call('635afce6-0ae8-4b84-90f5-837a2234002b')

    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch('ni.managementconnector.deploy.MCAlarm')
    @mock.patch('ni.managementconnector.platform.system.CafeXUtils')
    @mock.patch('ni.managementconnector.platform.system.get_expressway_version')
    def test_deploy_unsupported_version(self, mock_get_expressway_version, mock_cafeutils, mock_alarm, mock_get_package_version):

        DEV_LOGGER.info('+++++ test_deploy_unsupported_version')

        config = Config()
        deploy = Deploy(config)
        deploy._alarms = mock_alarm

        mock_cafeutils.get_package_version.return_value = "8.7-1.0.321171"
        mock_get_expressway_version.return_value = "8.6"
        deploy._quit = True
        deploy.deploy_fusion()

        mock_alarm.raise_alarm.assert_called_with('3e544328-598e-11e6-8b77-86f30ca893d3')

        mock_alarm.reset_mock()

        mock_cafeutils.get_package_version.return_value = "8.7-1.0.321171"
        mock_get_expressway_version.return_value = "8.7"
        deploy._quit = True
        deploy.deploy_fusion()

        mock_alarm.clear_alarm.assert_any_call('3e544328-598e-11e6-8b77-86f30ca893d3')

    @mock.patch("ni.managementconnector.platform.system.System.get_cpu_cores")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_disk")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_cpu")
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch('ni.managementconnector.deploy.CrashMonitor')
    @mock.patch('ni.managementconnector.config.config')
    @mock.patch('ni.managementconnector.cloud.atlas.Http')
    @mock.patch('ni.managementconnector.deploy.OAuth')
    @mock.patch('ni.managementconnector.deploy.MCAlarm')
    def test_zdeploy_no_service_connectors(self, mock_alarm, mock_oauth, mock_http, mock_config, mock_crash_montor, mock_get_package_version, mock_get_system_mem, mock_get_system_cpu, mock_get_system_disk, mock_get_cpu_cores):

        DEV_LOGGER.info('+++++ test_deploy_no_service_connectors')

        mock_get_package_version.return_value = "1.2.3"
        mock_get_cpu_cores.return_value = "2"

        deploy = Deploy(mock_config)


        def config_read(path, default={}):
            """ config class mock """

            if path == ManagementConnectorProperties.ALARMS_RAISED:
                return []
            elif path ==ManagementConnectorProperties.ENTITLED_SERVICES:
                return []
            elif path ==ManagementConnectorProperties.INSTALL_BLACK_LIST:
                return []
            else:
                return "dummy_val"

        mock_config.read.side_effect = config_read

        deploy._alarms = mock_alarm
        deploy._oauth = mock_oauth

        deploy._mercury_connection = Mercury(mock_config, mock_oauth)

        mock_oauth.get_access_token.return_value = "access_token"

        mock_http.post.return_value = {u'status': None, u'display_name': u'Fusion Management', u'registered_by': u'14a2a40a-8f38-4866-8f1a-e6226baf42c3', u'created_at': u'2014-11-14T09:43:49.744Z',
                                                      u'updated_at': u'2014-11-14T09:43:49.744Z', u'status_url': u'https://hercules.hitest.huron-dev.com/v1/connector_statuses/18',
                                                      u'organization_id': u'4214d345-7caf-4e32-b015-34de878d1158', u'connector_type': u'c_mgmt', u'version': u'X8.6PreAlpha0 (Test SW)',
                                                      u'cluster_id': u'', u'host_name': u'gwydlvm1186', u'provisioning_url': u'https://hercules.hitest.huron-dev.com/v1/management_connectors/3',
                                                      u'serial': u'0974F8FD', u'id': 18, u'provisioning': {u'connectors': [{u'connector_type': u'c_mgmt', u'version': u'8.6-1.0.521', u'display_name': u'Calendar Service', u'packages': [{u'tlp_url': u'https://aaa.bbb.ccc'}]}]}}

        mc_type = "c_mgmt"
        deploy._do_register_config_status(mc_type)

        mock_alarm.raise_alarm.assert_called_with('a144127e-57a5-11e5-8ccb-3417ebbf769a')

    @mock.patch('ni.utils.i18n.translate')
    @mock.patch('ni.managementconnector.platform.serviceutils.ServiceUtils.is_installing')
    @mock.patch('ni.managementconnector.deploy.MCAlarm')
    def test_stopped_alarm_is_suppressed_when_dependency_is_installing(self, mock_alarm, mock_installing, mock_translate):
        config = Config()
        deploy = Deploy(config)
        deploy._alarms = mock_alarm

        failed_connectors = ["Calendar Connector"]

        def install_side_effect(name):
            return name == "d_openj"

        mock_installing.side_effect = install_side_effect

        deploy._process_stopped_alarm(failed_connectors, "test", "%s failed")
        mock_alarm.raise_alarm.assert_not_called()

        mock_alarm.reset_mock()

        failed_connectors = ["Calendar Connector", "Call Connector"]
        mock_translate.return_value = "%s failed"

        deploy._process_stopped_alarm(failed_connectors, "test", "%s failed")
        mock_alarm.raise_alarm.assert_called_with("test", ["Call Connector failed\n"])

        mock_alarm.reset_mock()

        failed_connectors = ["Calendar Connector", "Call Connector"]

        mock_installing.side_effect = None
        mock_installing.return_value = None
        mock_translate.return_value = "%s failed"

        deploy._process_stopped_alarm(failed_connectors, "test", "%s failed")
        mock_alarm.raise_alarm.assert_called_with("test", ["Calendar Connector failed\nCall Connector failed\n"])



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
