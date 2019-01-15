#!/bin/sh

# bug 220953
# Changed c_mgmt.sh to execute the managementconnectormain from the home
# directory so that the local "platform" module does not cause a namespace
# clash with Python's built-in "platform" module.
# Exit with error signal if $PYTHON_code crashes so that firestarter
# will try to keep c_mgmt alive.
pushd ${HOME} >/dev/null 2>&1
read -d '' PYTHON_CODE << EOF
import __main__
import sys

C_MGMT_FILE = '/opt/c_mgmt/src/managementconnector/managementconnectormain.pyc'
__main__.__file__ = C_MGMT_FILE
sys.argv[0] = C_MGMT_FILE

sys.path.append('/opt/c_mgmt/src/')
import managementconnector.managementconnectormain

managementconnector.managementconnectormain.main()
EOF
python -c "$PYTHON_CODE" 2>&1
py_status=$?
popd >/dev/null 2>&1

exit $py_status

