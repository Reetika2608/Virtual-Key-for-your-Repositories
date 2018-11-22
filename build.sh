#!/bin/bash

# Source the universal methods
[ -f jenkins/packaging_methods ] && . "jenkins/packaging_methods"

clean_working_directory
install_python_component
sanitize_debian_package
include_files
remove_init_py_files
convert_po_to_mo
generate_symlinks
dublicate_and_symlink_transform
install_external_dependencies
package_debian
