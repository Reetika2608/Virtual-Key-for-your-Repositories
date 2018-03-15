#! /usr/bin/env python

"""
Transform to update any Cafe encrypted data so that it becomes encrypted with the currently active key
"""

import sys
import json
import subprocess
import filecmp
import logging
import ni.migration.transform
import re
import taacrypto

from ni.migration.cdbarchive import CDBArchive
from ni.migration.utils import Version

try:
    REENCRYPT_FUNC = taacrypto.reencrypt_with_active_key
except AttributeError:
    REENCRYPT_FUNC = None

DEV_LOGGER = logging.getLogger("developer.upgrade")

class CryptoErrorWrapper(Exception):
    ''' Wrapper for CryptoError exception '''
    def __init__(self, original_exception, detail):
        super(CryptoErrorWrapper, self).__init__()

        self.original_exception = original_exception
        self.detail = detail

def _reencrypt_field(field):
    ''' Reencrypt the field from the given table '''
    regex = r'"({cipher}.*?)"'

    def replace_string(match):
        ciphered_pass = match.group().strip('"')
        ciphered_pass = ciphered_pass.replace("\\","")
        return '"' + REENCRYPT_FUNC(ciphered_pass) + '"'

    crypto_exception = None
    failed_rows = []
    try:
        new_field = re.sub(regex, replace_string, field['value'])
        if new_field != field['value']:
            field['value'] = new_field
    except taacrypto.CryptoError as crypto_exception:
        # could also log row/uuid, but need to redact actual key
        DEV_LOGGER.info('Detail="Failed to reencrypt field" Reason="%s" Field="%s"' % (crypto_exception,
              field))
    if crypto_exception is not None:
        raise CryptoErrorWrapper(crypto_exception, field)

def reencrypt(cdb_table):
    ''' Function to traverse the table and find the fields needing reencryption and then reencrypt them '''
    crypto_exception = None
    failed_items = []
    for field in cdb_table:
        try:
            _reencrypt_field(field)
        except (KeyError, AttributeError):
            pass
        except CryptoErrorWrapper as crypto_exception:
            failed_items.append((field, crypto_exception.detail)) # keep for the acr

    if crypto_exception is not None:
        raise crypto_exception.original_exception

class CMgmtTranform(ni.migration.transform.Transform):
    """ Transform to reencrypt all Cafe CDB tables from being reloaded from their (by now, stale) CSV files."""
    from_version = None
    to_version   = None

    def run(self, cdb_archive):
        if REENCRYPT_FUNC:
            for name in ["cafeBlobConfiguration", "cafeStaticConfiguration"]:
                try:
                    DEV_LOGGER.info('Detail="Reencrypting strings in cdb table" Table="%s"', name)
                    reencrypt(cdb_archive[name])
                except (AttributeError, IndexError):
                    pass

transforms = ( # pylint: disable=C0103
    CMgmtTranform,
)

if __name__ == '__main__':
    RETURN = 0
    FROOT = sys.argv[1]
    KEYFILE = '/tandberg/persistent/systemkey'
    KEYFILE_DEFAULT = '/tandberg/persistent/systemkey.default'

    DEV_LOGGER.info('Detail="Starting cmgmt_transform"')

    # If we are moving to an old kit that will be using the well known system key,
    # we need to reencrypt the enciphered elements in the csv files that will be
    # used when we reboot.
    # We detect if this is necessary by seeing if the 'other' partition's system key file
    # matches the default.
    # Note that it may have been the 'systemprivate' upgrade script, which must run before this script,
    # that copied over the default key file.
    if filecmp.cmp(FROOT + KEYFILE, FROOT + KEYFILE_DEFAULT):
        ALT = subprocess.check_output(['bash', '-c', '. /etc/functions; get_alternate_root']).strip()
        INFO = json.load(open(FROOT + "/tandberg/etc/config.oldversioninfo"))
        VERSION = Version(INFO["version_code"], INFO["version_major"], INFO["version_minor"],
                          INFO.get("version_maintenance", 0))
        CDB_ARCHIVE = CDBArchive(VERSION,
                                 INFO['schema'], old_db_path="/mnt/harddisk/" + ALT + "/persistent/clusterdb/upgrade")
        REENCRYPT_FUNC = taacrypto.reencrypt_with_well_known_key

        for name in ["cafeBlobConfiguration", "cafeStaticConfiguration"]:
            try:
                reencrypt(CDB_ARCHIVE[name])

            # Ignore "Catching too general exception" warnings    pylint: disable=W0703
            except Exception as exp:
                DEV_LOGGER.exception('Detail="Exception when reencrypting csv files" Reason="%s"', exp)
                RETURN = 1

            if CDB_ARCHIVE[name].is_modified:
                with open(CDB_ARCHIVE[name].csv_filepath, "w") as fd:
                    DEV_LOGGER.info('Detail="Writing out CDB archive %s to %s"' % (name, CDB_ARCHIVE[name].csv_filepath))
                    fd.write(CDB_ARCHIVE[name].to_csv())

        DEV_LOGGER.info('Detail="Finished cmgmt_transform"')

    else:
        DEV_LOGGER.info('Detail="Skipped cmgmt_transform"')

    sys.exit(RETURN)
