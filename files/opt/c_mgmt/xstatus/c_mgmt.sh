#!/usr/bin/env bash

# Run the command, echo it's output to stdout and exit with it's exit code
output=$(python /opt/c_mgmt/src/managementconnector/xstatus/c_mgmt_xstatus.pyc)
py_status=$?
echo ${output} && exit ${py_status}