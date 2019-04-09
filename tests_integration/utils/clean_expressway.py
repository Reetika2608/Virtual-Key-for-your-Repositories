""" Clean Expressway """
import logging
import sys
import traceback

from tests_integration.utils.integration_test_logger import get_logger

sys.path.append("./")
sys.path.append("../../")

from tests_integration.utils import ci
from tests_integration.utils.cdb_methods import get_cluster_id, get_org_id, get_fms_host_url, delete_entire_cafe_blob
from tests_integration.utils.common_methods import wait_until_true, wait_for_defuse_to_finish
from tests_integration.utils.config import Config
from tests_integration.utils.fms import deregister_cluster
from tests_integration.utils.predicates import has_connector_pid_changed, is_ui_unresponsive
from tests_integration.utils.ssh_methods import get_and_log_management_connector_run_data, restart_connector, \
    run_ssh_command, run_xcommand

LOG = get_logger()


def restart_fmc(hostname, root_user, root_pass):
    """ Restart FMC; registered or unregistered """
    LOG.info("Restarting management connector...")
    starting_pid, starting_heartbeat_start_time, starting_mercury_route, starting_rd_device = \
        get_and_log_management_connector_run_data(hostname, root_user, root_pass)

    restart_connector(hostname, root_user, root_pass, "c_mgmt")
    wait_until_true(has_connector_pid_changed, 10, 1,
                    *(hostname, root_user, root_pass, "c_mgmt", starting_pid))


def restart_expressway(hostname, root_user, root_pass):
    """ restart expressway: and returns if the command was successful according to stdout """
    return "system restart complete" in run_ssh_command(hostname, root_user, root_pass, "restart")


def cloud_deregister(hostname, root_user, root_pass, admin_user, admin_pass, connectors, access_token):
    """ deregisters the Expressway through in FMS and waits for completion """
    cluster_id = get_cluster_id(hostname, admin_user, admin_pass)
    org_id = get_org_id(hostname, admin_user, admin_pass)
    fms_server = get_fms_host_url(hostname, admin_user, admin_pass).replace("https://", "")

    LOG.info("Running: cloud_deregister on: %s in org: %s", hostname, org_id)
    deregister_cluster(org_id, cluster_id, fms_server, access_token)
    LOG.info("Cluster has been de-registered. Wait for cleanup to complete on %s", hostname)

    return wait_for_defuse_to_finish(hostname, root_user, root_pass, admin_user, admin_pass, connectors)


def local_deregister(hostname, root_user, root_pass, admin_user, admin_pass, connectors):
    """ Run FMC Local deregister via xcommand """
    if "Defuse Complete" in run_xcommand(hostname, root_user, root_pass, "xcommand Cafe c_mgmt defuse"):
        LOG.info("Local Deregister triggered on %s", hostname)
        wait_for_defuse_to_finish(hostname, root_user, root_pass, admin_user, admin_pass, connectors)
    else:
        LOG.error("Failure: Local deregister was not triggered on %s", hostname)


def uninstall_connectors(hostname, root_user, root_password, connectors):
    """ Run manual uninstall of connectors """
    # Don't allow c_mgmt to be uninstalled
    if "c_mgmt" in connectors:
        if isinstance(connectors, dict):
            connectors.pop("c_mgmt")
        elif connectors(connectors, list):
            connectors.remove("c_mgmt")

    LOG.info("Kicking a fire and forget uninstall on: %s of %s", hostname, connectors)
    run_ssh_command(hostname, root_user, root_password,
                    "echo '{}' > /tmp/pkgs/new/files.rem".format(" ".join(connectors)))


def main():
    """ Main method that cleans up the Expressway """
    access_token = None
    refresh_token = None
    try:
        config = Config()
        hostname = sys.argv[1]
        access_token, refresh_token, session = ci.get_new_access_token(config.org_admin_user(),
                                                                       config.org_admin_password())

        try:
            finished = cloud_deregister(hostname, config.exp_root_user(), config.exp_root_pass(),
                                        config.exp_admin_user(), config.exp_admin_pass(), config.expected_connectors(),
                                        access_token)
        except Exception as error:
            LOG.info("Cloud Deregister didn't complete, maybe wasn't required: %r %s: %s", error, error.__str__(),
                     traceback.format_exc())
            finished = False

        if finished is False:
            # If the cloud deregister did not finish or completely work try another local deregister
            local_deregister(hostname, config.exp_root_user(), config.exp_root_pass(), config.exp_admin_user(),
                             config.exp_admin_pass(), config.expected_connectors())

        # Make sure everything is actually uninstalled, with a fire and forget uninstall
        uninstall_connectors(hostname, config.exp_root_user(), config.exp_root_pass(), config.expected_connectors())
        delete_entire_cafe_blob(hostname, config.exp_admin_user(), config.exp_admin_pass())

        if is_ui_unresponsive(hostname):
            successful_restart = restart_expressway(hostname, config.exp_root_user(), config.exp_root_pass())
            LOG.info("Attempted Expressway restart, successful?=%s", successful_restart)
        else:
            restart_fmc(hostname, config.exp_root_user(), config.exp_root_pass())

    except Exception as error:
        LOG.error("Exception raised from main, %r %s: %s", error, error.__str__(), traceback.format_exc())
    finally:
        # Clean up any tokens we got at the start
        if access_token:
            ci.delete_ci_access_token(access_token)
        if refresh_token:
            ci.delete_ci_refresh_token(refresh_token)


if __name__ == "__main__":
    logging.basicConfig()
    main()
