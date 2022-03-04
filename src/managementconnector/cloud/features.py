""" Class to Manage Feature Entitlement """

import json
import traceback
import jsonschema
from urllib.parse import urlparse as urllib_parse

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud import schema
from managementconnector.platform.http import Http

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class Features(object):
    """ Features Class """

    def __init__(self, config, oauth):
        """ Constructor """
        self._config = config
        self._oauth = oauth
        self._last_write = None

    def _get_features(self):
        """ Get a list of Features and validate against schema """
        features_resp = None
        try:
            features_url = self.build_features_url()
            if features_url:
                features_resp = Http.get(features_url, self._oauth.get_header(),
                                         schema=schema.FEATURES_TOGGLE_RESPONSE)
            else:
                DEV_LOGGER.error('Detail="FMC_Features features_url creation failed"')

        except ValueError:
            DEV_LOGGER.info('Detail="ValueError occured when loading json - return response as-is"')
        except (jsonschema.ValidationError, KeyError) as validation_exc:
            DEV_LOGGER.error('Detail="FMC_Features ValidationError when validating json:%s, stacktrace=%s"'
                             % (repr(validation_exc), traceback.format_exc()))
            # Not re-raising exception as feature thread is not monitored for restart
            return None

        return features_resp

    def update_latest_features(self):
        """ Gets latest features and writes to database """
        features = self._get_features()
        DEV_LOGGER.debug('Detail="FMC_Feature update_latest_features: updating feature toggles"')

        if features:
            if ManagementConnectorProperties.FEATURES_GROUP in features:
                clean_features = Features.audit_features(features[ManagementConnectorProperties.FEATURES_GROUP])
                full_path = ManagementConnectorProperties.BLOB_CDB_PATH + ManagementConnectorProperties.FEATURES_ENTRIES

                # Not using write blob to circumnavigate caching in config
                if clean_features != self._last_write:
                    # Reduce the number of writes to db if data hasn't changed
                    DEV_LOGGER.debug('Detail="FMC_Feature features changed: last: %s latest: %s"',
                                     self._last_write, clean_features)
                    self._last_write = clean_features
                    self._config.write(full_path, {"value": json.dumps(clean_features)})

    def get_user_id(self):
        """Get org id"""
        uid = None
        oauth_details = self._config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)
        if "id" in oauth_details:
            uid = oauth_details['id']
        else:
            DEV_LOGGER.debug('Detail="FMC_Feature machine account user id not present"')
            if "location" in oauth_details:
                location = oauth_details['location']
                parts = location.split('/')
                uid = parts[-1]

        return uid

    def build_features_url(self):
        """ Concatenate required features parts """
        full_url = None

        host = self._config.read(ManagementConnectorProperties.FEATURES_HOST)
        url = self._config.read(ManagementConnectorProperties.FEATURES_URL)
        user_id = self.get_user_id()

        if host and url and user_id:
            parsed_host = urllib_parse(host)
            full_url = "{0}://{1}/{2}{3}".format(parsed_host.scheme, parsed_host.hostname, url, user_id)

        DEV_LOGGER.debug('Detail="FMC_Features url: %s"', full_url)

        return full_url

    @staticmethod
    def audit_features(features):
        """ Remove unrelated FMC features, and leave key:value, feature:true/false """
        clean_features = dict()
        for feature in features:
            if feature['key'].startswith(ManagementConnectorProperties.FEATURES_PREFIX):
                clean_features[feature['key']] = feature[ManagementConnectorProperties.FEATURE_VAL_ID]

        DEV_LOGGER.debug('Detail="FMC_Features audit_features returning clean features: %s"' % clean_features)
        return clean_features

    @staticmethod
    def compare_features(config, cached_list):
        """ audits features and returns threads to start """
        latest_features = config.read(ManagementConnectorProperties.FEATURES_ENTRIES)
        delta = dict()
        if latest_features:
            for key, value in latest_features.items():
                if key not in cached_list or (key in cached_list and value != cached_list[key]):
                    DEV_LOGGER.debug('Detail="FMC_Features feature: %s:%s has changed"', key, value)
                    delta[key] = value

        return latest_features, delta
