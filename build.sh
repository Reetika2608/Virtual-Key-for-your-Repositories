#!/bin/bash

# Source the universal methods
[ -f jenkins/packaging_methods ] && . "jenkins/packaging_methods"

clean_working_directory
install_python_component
sanitize_debian_package
package_debian