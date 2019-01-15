#!/usr/bin/env python

# Ignore "Catch Exception" warnings.                pylint: disable=W0703
# Ignore "Unused import" warning.                   pylint: disable=W0614
# Ignore "Wildcard import" warning.                 pylint: disable=W0401

"""\
Module to provide utilities for accessing cluster related items from the Cluster DB
"""

import logging


from base_platform.expressway.cdb.restclient import ClusterDatabaseRestClient

# import logging setup, to preregister some acr ignore filters
import base_platform.expressway.logframework.setup as logging_setup  # pylint: disable=unused-import

DEV_LOGGER = logging.getLogger("developer.replication")
ADMIN_LOGGER = logging.getLogger("administrator.replication")

# Cluster DB configuration tables
VCSCONFIGURATIONBRIEF_TABLE = '/configuration/vcsconfigurationbrief'
VCSCONFIGURATIONFULL_TABLE = '/configuration/vcsconfiguration'
ALTERNATES_TABLE = '/configuration/alternates'
ALTERNATES_MASTER_TABLE = '/configuration/alternatesmaster'
CLUSTERPEER_CONFIG_TABLE = '/configuration/clusterpeer'

# ClusterDB Status Tables
CLUSTERPEER_STATUS_TABLE = '/status/clusterpeer'


class ClusterConfigurationException(Exception):
    """Exception class for cluster configuration."""
    pass


class ClusterDBPeerData(ClusterDatabaseRestClient):
    """
    Class to retrieve alternates and peer data from ClusterDB due to the
    deprecation of the XMLAPI paths.
    """

    def __init__(self):
        ClusterDatabaseRestClient.__init__(self)

    # Public API

    def get_local_peer_index(self):
        """
        Retrieve ourselves from status using the local_peer field
        Using the peer field, do a clusterpeer lookup and grab the index field
        """
        peer_addrs = [peer['peer'] for peer in self._get_clusterpeer_status_records(local=True)]
        if len(peer_addrs) < 1:
            return -1
        peer_rec = self.get_peer_by_address(peer_addrs[0])

        return peer_rec['index']

    def get_config_master_index(self):
        """
        Return the local peer address
        addr_type:
            IP -> Alternate Address used by H323 and SIP
            CDB -> Peer Address used by ClusterDB
        """
        return self._get_alternates_master_record()['master_idx']

    def get_config_master_address(self, addr_type='IP'):
        """
        Return the local peer address
        addr_type:
            IP -> Alternate Address used by H323 and SIP
            CDB -> Peer Address used by ClusterDB
        """
        field_of_interest = None
        if addr_type == 'CDB':
            field_of_interest = 'cdb_address'
        elif addr_type == 'IP':
            field_of_interest = 'ip_address'
        else:
            raise ValueError('addr_type: ' + addr_type + ' is not IP or CDB.')

        index = self.get_config_master_index()
        master_alternate = self.get_alternate_by_index(index)
        return master_alternate[field_of_interest]

    def get_peer_by_address(self, address):
        """
        Gets a peer record from a clusterdb peer address
        """
        peer_recs = self._get_clusterpeer_config_records(peer=address)
        if len(peer_recs) < 1:
            return self._default_clusterpeer_record()
        return peer_recs[0]

    def get_alternate_by_index(self, index):
        """
        Gets an alternate from clusterdb using the provided index
        """
        alternate_recs = self._get_alternates_config_records(index=index)
        # we should always have one record
        if len(alternate_recs) == 0:
            DEV_LOGGER.error('Detail="Could not retrieve peer at position" Index="%s"', index)
            raise ClusterConfigurationException()
        return alternate_recs[0]

    # Private API
    def _get_alternates_config_records(self, ip_address=None, cdb_address=None, index=None):
        """
        Get configuration/clusterpeer from cdb
        if peer provided, use as query
        else
        if index provided use as query
        else
        get all peers
        """
        alternates_path = ALTERNATES_TABLE + '?peer=local'
        if ip_address is not None:
            alternates_path = ALTERNATES_TABLE + '/ip_address/%s?peer=local' % ip_address
        elif cdb_address is not None:
            alternates_path = ALTERNATES_TABLE + '/cdb_address/%s?peer=local' % cdb_address
        elif index is not None:
            alternates_path = ALTERNATES_TABLE + '/index/%s?peer=local' % index

        alternates_records = self.get_records(alternates_path)
        DEV_LOGGER.debug('Detail="Getting Alternates from CDB" Path="%r" Alternates="%r"',
                         alternates_path, alternates_records)
        return alternates_records

    def _get_alternates_master_record(self):
        """
        Get the record from configuration/alternatesmaster
        """
        master_record = self.get_records(ALTERNATES_MASTER_TABLE)
        DEV_LOGGER.debug('Detail="Getting Alternates Master Record" Alternates-Master-Record="%r"',
                         master_record)
        if len(master_record) < 1:
            raise ClusterConfigurationException()
        return master_record[0]

    def _get_clusterpeer_config_records(self, peer=None, index=None):
        """
        Get configuration/clusterpeer from cdb
        if peer provided, use as query
        else
        if index provided use as query
        else
        get all peers
        """
        peer_path = CLUSTERPEER_CONFIG_TABLE + '?peer=local'
        if peer is not None:
            peer_path = CLUSTERPEER_CONFIG_TABLE + '/peer/%s?peer=local' % peer
        elif index is not None:
            peer_path = CLUSTERPEER_CONFIG_TABLE + '/index/%s?peer=local' % index

        peer_records = self.get_records(peer_path)
        DEV_LOGGER.debug('Detail="Getting Peers from CDB" Path="%r" Peers="%r"',
                         peer_path, peer_records)
        return peer_records

    def _get_clusterpeer_status_records(self, local=False):
        """
        Get status/clusterpeer from cdb
        """
        path = CLUSTERPEER_STATUS_TABLE
        if local:
            path = path + '/local_peer/true'
        path = path + '?peer=local'
        peer_status_records = self.get_records(path)
        DEV_LOGGER.debug('Detail="Getting Peer Status from CDB" Peer-Status="%r" Local="%r"',
                         peer_status_records, local)
        return peer_status_records

    @staticmethod
    def _default_clusterpeer_record():
        """
        Return an empty clusterpeer record in the same format as
        configuration/clusterpeer
        """
        return {
            'uuid': '',
            'index': 0,
            'peer': '',
        }
