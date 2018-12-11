#!/usr/bin/env bash

set -e

usage(){
    echo "Usage:    ./build_and_upgrade.sh -c <command> -t <target>"
    echo "          -c   Command: {clean_install|upgrade}"
    echo "          -t   Target: sets the target you want to upgrade"
    echo "          -p   Password: sets the password for your target"
    echo "          -v   Version: sets the version number of the build"
    echo "          -h   Help: Displays the help option Display this help message"
}

upgrade(){
    # Set the version number to installed version + 1, if the -v option was not supplied
    INSTALLED_VERSION=$(sshpass -p ${TARGET_PASSWORD} ssh root@${TARGET} dpkg  -l | grep c_mgmt | awk '{print $3}' | cut -d "." -f 4)
    if [ -z "${VERSION}" ]; then
        VERSION=$((INSTALLED_VERSION+1))
    fi

    [ "$INSTALLED_VERSION" = "$VERSION" ] && echo "[upgrade] Error: Can't upgrade to same version as installed: ${VERSION}" && exit 1

    echo "[upgrade] Upgrading: ${TARGET} from ${INSTALLED_VERSION} to ${VERSION}"
    ./build.sh ${VERSION}
    install
}

clean_install(){
    echo "[clean_install] Fresh installing: ${TARGET} with version ${VERSION}"
    uninstall
    ./build.sh ${VERSION}
    install
}

install(){
    echo "[install] Starting install on ${TARGET}"
    sshpass -p ${TARGET_PASSWORD} scp ./debian/_build/c_mgmt.deb root@${TARGET}:/tmp/pkgs/new/
}

uninstall(){
    echo "[uninstall] Starting uninstall on ${TARGET}"
    sshpass -p ${TARGET_PASSWORD} ssh root@${TARGET} 'echo c_mgmt > /tmp/pkgs/new/files.rem'
}


if [[ $# -eq 0 ]] ; then
    usage
    exit 0
fi

# Settings defaults
TARGET_PASSWORD=x
while getopts ":ht:pv:c:" opt; do
    case ${opt} in
        h )
          usage
          exit 0
          ;;
        t )
            TARGET=$OPTARG
            ;;
        p )
            TARGET_PASSWORD=$OPTARG
            ;;
        v )
            VERSION=$OPTARG
            ;;
        c )
            CMD=$OPTARG
            ;;
        \? )
          echo "Invalid Option: -$OPTARG" 1>&2
          usage
          exit 1
          ;;
    esac
done
shift $((OPTIND -1))

[ -z "${CMD}" ] && echo "Command must be set: use option: -c" && usage && exit 1
[ -z "${TARGET}" ] && echo "Target must be set to install/upgrade: use option: -t" && usage && exit 1

if [ "${CMD}" = "upgrade" ]; then
    upgrade
elif [ "${CMD}" = "clean_install" ]; then
    clean_install
fi
