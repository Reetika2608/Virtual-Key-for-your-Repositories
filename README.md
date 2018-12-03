### Running Unittests locally 

`setup_test_environment.sh` is a script to set up a build environment capable of running the unit tests. This will:
1. Create a python virtual environment.
2. Install all the python packages management connector needs to run test into this environment.
3. Install the _stubs_ module into the environment. Stubs fakes out all the expressway platform touch points where FMC leans on resources outside of this repo. The code is located at `test_environment/stubs/`

To run the unit tests in a terminal run:
1. `source test_environment/setup_test_environment.sh`
2. `nosetests ni/tests/managementconnector/`

Once you have run `setup_test_environment.sh` you can use the virtual environment to run the tests locally in PyCharm. Configuration will be something like:
1. Go to **Preferences** > **Project: management-connector** > **Project Interpreter**
2. Click the wheel in the top right corner and click **Add**
3. Choose **Existing environment** and click the ellipsis button
4. Find your virtual environment and select it: `your_checkout_location/management-connector/test_environment/venv/bin/python`
 

### Cleaning your current working directory
Running the following command will delete all staging/build directories, pyc files, debians etc.

```python setup.py clean```

### Building FMC
To Build a c_mgmt.deb run the following script, this will clean the working director, compile and install FMC,
and package all required elements for the c_mgmt debian

```./build.sh```

### Development in a Docker environment
To build a c_mgmt.deb from within docker you can run the following commands. This will build a docker image from the
`Dockerfile`, where `fmc-build` is a docker image name.
The commands below will build a Docker image, and start an interactive container with access via a bash shell.
From there you have a build environment, with the CWD added to the container for access to FMC source, and pip test requirements installed.
You can run unit tests, complete a build of FMC, all from within this container.

```
docker build -t fmc-build .
docker run -it fmc-build /bin/bash
```

#### Example Commands run in the fmc-build Docker container
```
# Running Unit tests
root@acdc32ee8df8:/management-connector# cd test_environment/stubs
root@acdc32ee8df8:/management-connector/test_environment/stubs# python setup.py install
root@acdc32ee8df8:/management-connector/test_environment/stubs# cd -
root@acdc32ee8df8:/management-connector# nosetests ni/tests/managementconnector/

# Doing a Build of FMC debian
root@acdc32ee8df8:/management-connector# ./build.sh
```


### Security
* Threat Model ID: [21796](https://wwwin-tb.cisco.com/www/threatBuilder.html?id=21796)
* Threat Model Doc: [EDCS-1496496](https://docs.cisco.com/share/page/site/nextgen-edcs/document-details?nodeRef=workspace://SpacesStore/f12dde6e-2b99-4f02-9634-399d7f2858d9)
* IP Central: https://ipcentral.cisco.com/ipcentral/jsp/ipcentral.jsp?component=ProjectView&entityId=126815985
* Static Analysis: pylint is automatically run during the build process. Any new static analysis findings will cause the build to fail.
