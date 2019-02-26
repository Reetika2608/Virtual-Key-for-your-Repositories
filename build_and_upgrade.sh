#!/usr/bin/env bash

# Source the universal methods
[[ -f jenkins/packaging_methods ]] && . "jenkins/packaging_methods"

usage(){
    echo "Usage:    ./build_and_upgrade.sh -c <command> -t <target>"
    echo "          -c   Command: {build|clean_install|upgrade}"
    echo "          -t   Target: sets the target you want to upgrade"
    echo "          -p   Password: sets the password for your target"
    echo "          -v   Version: sets the version number of the build"
    echo "          -h   Help: Displays the help option Display this help message"
}

build(){
    BUILD_NUMBER=$1
    if [[ -z "${BUILD_NUMBER}" ]]
    then
        BUILD_NUMBER=12345
    fi

    clean_working_directory
    install_python_component
    sanitize_debian_package
    include_files
    remove_init_py_files
    convert_po_to_mo
    generate_symlinks
    duplicate_and_symlink_transform
    audit_import_paths
    install_external_dependencies
    generate_debian_version ${BUILD_NUMBER}
    remove_group_write_permissions
    package_debian
    audit_debian_contents
}

add_to_known_hosts(){
    # Check and create the ssh directory, which may not exist in the docker image
    [[ ! -d ~/.ssh/ ]] && mkdir ~/.ssh/
    ssh-keyscan -H ${TARGET} >> ~/.ssh/known_hosts
}

upgrade(){
    add_to_known_hosts
    # Set the version number to installed version + 1, if the -v option was not supplied
    INSTALLED_VERSION=$(sshpass -p ${TARGET_PASSWORD} ssh root@${TARGET} dpkg  -l | grep c_mgmt | awk '{print $3}' | cut -d "." -f 4)
    if [[ -z "${VERSION}" ]]; then
        VERSION=$((INSTALLED_VERSION+1))
    fi

    [[ "$INSTALLED_VERSION" = "$VERSION" ]] && echo "[upgrade] Error: Can't upgrade to same version as installed: ${VERSION}" && exit 1

    echo "[upgrade] Upgrading: ${TARGET} from ${INSTALLED_VERSION} to ${VERSION}"
    build ${VERSION}
    install
}

clean_install(){
    echo "[clean_install] Fresh installing: ${TARGET} with version ${VERSION}"
    add_to_known_hosts
    uninstall
    build ${VERSION}
    install
}

install(){
    echo "[install] Starting install on ${TARGET}"
    sshpass -p ${TARGET_PASSWORD} scp ./debian/_build/c_mgmt.deb root@${TARGET}:/tmp/pkgs/new/
    if [[ ${WAIT_FOR_INSTALL} == true ]]; then
        wait_for_install
    fi
}

uninstall(){
    echo "[uninstall] Starting uninstall on ${TARGET}"
    sshpass -p ${TARGET_PASSWORD} ssh root@${TARGET} 'echo c_mgmt > /tmp/pkgs/new/files.rem'
}

wait_for_install(){
    echo "Waiting for install..."
    for i in `seq 1 45`;
    do
        installed_version=$(sshpass -p ${TARGET_PASSWORD} ssh root@${TARGET} '(dpkg -s c_mgmt || true) | grep Version')

        if [[ ${installed_version} == *"${VERSION}" ]]; then
            install_status=$(sshpass -p ${TARGET_PASSWORD} ssh root@${TARGET} 'dpkg -s c_mgmt | grep Status')

            if [[ ${install_status} == *"install ok installed" ]]; then
                echo -e "\nc_mgmt ${installed_version} installed successfully"
                exit 0
            fi
        fi
        sleep 1
        echo -ne "Waited for $i of 45 seconds for c_mgmt to install successfully"\\r
    done

    echo -e "\nERROR - c_mgmt failed to install. Current status:"
    echo $(sshpass -p ${TARGET_PASSWORD} ssh root@${TARGET} 'dpkg -s c_mgmt')
    exit 1
}


if [[ $# -eq 0 ]] ; then
    usage
    exit 0
fi

# Settings defaults
TARGET_PASSWORD=x
while getopts ":ht:pv:c:w" opt; do
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
        w )
            WAIT_FOR_INSTALL=true
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

if [ "${CMD}" = "build" ]; then
    build ${VERSION}
elif [ "${CMD}" = "upgrade" ]; then
    [ -z "${TARGET}" ] && echo "Target must be set to install/upgrade: use option: -t" && usage && exit 1
    upgrade
elif [ "${CMD}" = "clean_install" ]; then
    [ -z "${TARGET}" ] && echo "Target must be set to install/upgrade: use option: -t" && usage && exit 1
    clean_install
fi
