#!/bin/bash
#===============================================================================
#
#         FILE:  setup_test_environment.sh
#
#        USAGE:  setup_test_environment.sh
#                  or 
#                source setup_test_environment.sh
#
#  DESCRIPTION:  This script runs virtualenv to set up the virtual environment
#                folder to contain the desired version of python as well as runs
#                pip to install packages specified in the requirements.txt file
#                in this same folder.
#
#        NOTES:  The first usage method will run the script but will not enter
#                into the virtual environment until explicitly invoked with the
#                activate command found within the virtualenv folder created by
#                by the script. The second method will run the script and
#                immediately enter the virtual environment. One additional note,
#                it was intentionally not written to use virtualenvwrapper due
#                to the desire to have this folder self-contained in 
#                anticipation of continuous integration. More information on
#                virtualenv is available here:  http://www.virtualenv.org/
#
# REQUIREMENTS:  This script requires virtualenv and pip are installed.
#
#===============================================================================

set -e

# Params for virtualenv, expected to be tweaked for your project needs.
VE_DIR='venv'
VE_PYTHON='python2.7'
VE_PROMPT='(venv) '

function prep_env()
{
    pushd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null

    # Run virtualenv to create the desired version of python.
    virtualenv \
        --python "${VE_PYTHON}" \
        --prompt "${VE_PROMPT}" \
        --distribute \
        ${VE_DIR}
    if [[ $? -ne 0 ]]; then return 0; fi

    # Activate the virtual environment.
    source "${VE_DIR}/bin/activate"
    if [[ $? -ne 0 ]]; then return 0; fi

    # Run pip to installed required packages for this project.
    pip install -r requirements.txt
    if [[ $? -ne 0 ]]; then deactivate; return 0; fi

    # If script was not sourced, remind the user.
    if [[ "$0" != "-bash" ]]; then
        echo ""
        echo "Since you did not 'source' this script, be sure to activate your "
        echo "virtual environment before continuing. For example: "
        echo ""
        echo " source ${VE_DIR}/bin/activate"
        echo ""
        echo "After activation, simply run 'deactivate' in your shell to return "
        echo "your normal environment."
        echo ""
    fi
}

prep_env
