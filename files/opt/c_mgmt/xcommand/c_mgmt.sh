#!/usr/bin/env bash

# Run the command, echo it's output to stdout and exit with it's exit code
# Command params must be a string of parameters to be parsed by the xcommand
output=$(python /opt/c_mgmt/src/managementconnector/xcommand/c_mgmt_xcommand.pyc $1 "${2}")
py_status=$?
echo ${output} && exit ${py_status}