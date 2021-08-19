#!/usr/bin/env bash

# change default LD_LIBRARY_PATH to /opt/c_mgmt/ssl/lib64
# This is done inorder for management container to use it's own SSL
# SSl Version: CiscoSSL 1.0.2y.6.2.403-fips
export LD_LIBRARY_PATH='/opt/c_mgmt/ssl/lib64/':$LD_LIBRARY_PATH

# Run the command, echo it's output to stdout and exit with it's exit code
# Command params must be a string of parameters to be parsed by the xcommand
output=$(/opt/c_mgmt/python/bin/python /opt/c_mgmt/src/managementconnector/xcommand/c_mgmt_xcommand.pyc $1 "${2}")
py_status=$?
echo ${output} && exit ${py_status}