### Running Unittests locally 

* Create a virtual environment
    * `virtualenv venv`
    * `source venv/bin/activate`
* Go to woodlib/python/c_mgmt_lib
* Run sudo ./prep_unittest_env.sh
* Run ./install_dependecies.sh
* In PyCharm, select woodlib/python/managementconnector/ni/test/managementconnector and Run/Debug the tests 

### Security
* Threat Model ID: [21796](https://wwwin-tb.cisco.com/www/threatBuilder.html?id=21796)
* Threat Model Doc: [EDCS-1496496](https://docs.cisco.com/share/page/site/nextgen-edcs/document-details?nodeRef=workspace://SpacesStore/f12dde6e-2b99-4f02-9634-399d7f2858d9)
* IP Central: https://ipcentral.cisco.com/ipcentral/jsp/ipcentral.jsp?component=ProjectView&entityId=126815985
* Static Analysis: pylint is automatically run during the build process. Any new static analysis findings will cause the build to fail.
