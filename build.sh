#!/bin/bash

# Source the universal methods
[[ -f jenkins/packaging_methods ]] && . "jenkins/packaging_methods"

BUILD_NUMBER=$1
if [ -z "${BUILD_NUMBER}" ]
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
package_debian
