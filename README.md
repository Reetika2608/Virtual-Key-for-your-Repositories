### Running Unittests locally 

* Create a virtual environment
    * `virtualenv venv`
    * `source venv/bin/activate`
* Go to woodlib/python/c_mgmt_lib
* Run sudo ./prep_unittest_env.sh
* Run ./install_dependecies.sh
* In PyCharm, select woodlib/python/managementconnector/ni/test/managementconnector and Run/Debug the tests 

### Cleaning your current working directory
Running the following command will delete all staging/build directories, pyc files, debians etc.
* ```python setup.py clean```

### Building FMC
To Build a c_mgmt.deb run the following script, this will clean the working director, compile and install FMC,
and package all required elements for the c_mgmt debian
    * `./build.sh`

### Building FMC within Docker
To build a c_mgmt.deb from within docker you can run the following commands. This will build a docker image from the
`Dockerfile`, where `fmc-build` is a docker image name and `~/git/management-connector/` is the root of your FMC checkout

```
docker build -t fmc-build .
docker run -v ~/git/management-connector/:/management-connector fmc-build
```

### Security
* Threat Model ID: [21796](https://wwwin-tb.cisco.com/www/threatBuilder.html?id=21796)
* Threat Model Doc: [EDCS-1496496](https://docs.cisco.com/share/page/site/nextgen-edcs/document-details?nodeRef=workspace://SpacesStore/f12dde6e-2b99-4f02-9634-399d7f2858d9)
* IP Central: https://ipcentral.cisco.com/ipcentral/jsp/ipcentral.jsp?component=ProjectView&entityId=126815985
* Static Analysis: pylint is automatically run during the build process. Any new static analysis findings will cause the build to fail.
