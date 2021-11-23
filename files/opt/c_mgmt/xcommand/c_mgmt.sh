#!/usr/bin/env bash

# Change link loader path to point point to libs packed with FMC
export LD_LIBRARY_PATH='/opt/c_mgmt/lib64':$LD_LIBRARY_PATH

# Run the command, echo it's output to stdout and exit with it's exit code
# Command params must be a string of parameters to be parsed by the xcommand
output=$(/opt/c_mgmt/python/bin/python /opt/c_mgmt/src/managementconnector/xcommand/c_mgmt_xcommand.pyc $1 "${2}")
py_status=$?
echo ${output} && exit ${py_status}