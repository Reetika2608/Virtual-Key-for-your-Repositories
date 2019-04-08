### FMC Overview

The Fusion Management Connector, running on-premise on Expressway, has mainly 2 responsibilities:
* Sending heartbeats to the cloud (FMS) and handling the hearbeat reply
* Upgrade the other connectors running on the Expressway

For the example commands below, please ssh using root user to the Expressway. 

#### FMC database
FMC uses the CDB (clustered database). FMC uses basically just 2 tables, and the entries persisted in the tables are JSON values.
#### Templates & config generation
Example: `cat /opt/c_mgmt/etc/config/c_mgmt.json`
Templates are there to provide data access without reading from the database: as a developer, the template and config 
generation provide a JSON file that can be read. The JSON file's data will be updated (via notifications) when the database is updated.

New data members should be added to the template and read from the config JSON files. 

#### Alarms 
The alarm range is 60000 - 69999. Each service is given a range of 100 alarms.
See for example `/var/run/connector_name/status.json`
Alarms are defined in i.e. `/mnt/harddisk/current/fusion/manifest/c_cal.json`:
```
"alarms":
    {
        "start": "60050",
        "end": "60099",
        "suppress": ["60050","60051","60070","15004","15010","15011","15019"],
        "external": ["15004", "15010", "15011", "15019"]
    }
```
where alarms in the `suppress` list are not sent, whereas alarms in the `external` list *are* sent.

To get details about alarms:
`alarm list -a`
#### Manifests
TODO: add something here

#### The package manager & installing debians
TODO: add something here

`dpkg -s c_mgmt`

To figure out install problems: `vi /mnt/harddisk/log/packagesd.log`

#### Firestarter & service startup
TODO: add something here

#### Xcommand & Xstatus
Everything under `/files` will get stuffed into the Debian package

`Xcommand cafe c_mgmt`//telling cafe to look import the c_mgmt.py module under  `/files`

Expressway run on Python 2.7. For compiled Python, pyc files NEEDS to run on the same magic numbers. FMC now has its own Python 2.7.15. 

We have wrappers so we can use i.e Python 3 in FMC, but still invoke the 2.7.15 commands on expressway. 
Commands:
`xCommand Cafe c_mgmt` to list commands. Example commands can be for example start and stop connectors

The user interface uses Xstatus to build up values in the PHP.

#### sbin requests & root escalation
TODO: add something here
#### PHP & the fuse flow
TODO: add something here
#### Certificate management
Certs are inside the Debian, to make FMC able to talk with FMS, CI and other dependencies. Need admin approval to use those certs, this is done via a button in the UI. 

The customer can add certs himself, if he chooses to not use the certs provided by Cisco.
FMC is verifying the server certs. 

#### CDB transforms
TODO: add something here
#### Thread lifecycle management
There are 2 threads that do *not* run on a peer, only on master: U2C and the machine_runner thread

The watchdog runner will keep and eye on the connector and restart if necessary.

Default script to run all plugin services: `/etc/service_template`

To start a service, for example cal: `/opt/c_cal/bin/c_cal.sh`. For specific start up behaviour, see the config files
under `/etc/init.d/`, for example `/etc/init.d/c_mgmt`

##### The main deploy / heartbeating thread
Thread that does the install/upgrades and handles the heartbeats. Upgrades done in a separate thread (since FMC will send heartbeats even during an upgrade of a connector)
##### Remote dispatcher thread & commands
TODO: add something here
##### U2C
Thread that will talk with the U2C service every hour and get which URLs to use. If URLs are changed, this gets persisted in the database.
##### Machine password rotation thread and oauth ojects
Updates the machine account; every 60 days it updates the password.

### Running Unittests locally 

`setup_test_environment.sh` is a script to set up a build environment capable of running the unit tests. This will:
1. Create a python virtual environment.
2. Install all the python packages management connector needs to run test into this environment.

To run the unit tests in a terminal run:
1. `source test_environment/setup_test_environment.sh`
2. `nosetests tests/managementconnector/`

Once you have run `setup_test_environment.sh` you can use the virtual environment to run the tests locally in PyCharm. Configuration will be something like:
1. Go to **Preferences** > **Project: management-connector** > **Project Interpreter**
2. Click the wheel in the top right corner and click **Add**
3. Choose **Existing environment** and click the ellipsis button
4. Find your virtual environment and select it: `your_checkout_location/management-connector/test_environment/venv/bin/python`

### Pylint
* You can run pylint manually using `setup.py`, sample command below
* You can also integrate pylint into Pycharm by installing the [pylint plugin](https://plugins.jetbrains.com/plugin/11084-pylint) and marking the `src` folder as "Sources root"

`python setup.py pylint`

### Cleaning your current working directory
Running the following command will delete all staging/build directories, pyc files, debians etc.

`python setup.py clean`

### Building FMC
To Build a c_mgmt.deb run the following script, this will clean the working director, compile and install FMC,
and package all required elements for the c_mgmt debian

`./build_and_upgrade.sh -c build`

### Building and Upgrading

For faster development you can add a bash alias to build and upgrade your FMC on a target Expressway. To do this add the following line to your
`~/.bash_aliases` file and ensure it's been sourced correctly.

`alias upgrade_<hostname>='cd ~/git/management-connector/ && ./build_and_upgrade.sh -c upgrade -t <taget_expressway_ip> -w'`
`alias doc_upgrade_<hostname>='cd ~/git/management-connector/ && docker run -it --mount type=bind,source="$(pwd)/",target="/management-connector" fmc-build ./build_and_upgrade.sh -c upgrade -t <target_expressway> -w'`

The `-c` option specifies the different command options, `-t` specifies the target you want to upgrade, and the `-w` specifies that you
want to wait for the install of the debian to complete


### Development in a Docker environment
To build a c_mgmt.deb from within docker you can run the following commands. This will build a docker image from the
`Dockerfile`, where `fmc-build` is a docker image name.
The commands below will build a Docker image, and start an interactive container with access via a bash shell.
From there you have a build environment, with the CWD added to the container for access to FMC source, and pip test requirements installed.
You can run unit tests, complete a build of FMC, all from within this container.

```
docker build -t fmc-build .
docker run -it --mount type=bind,source="$(pwd)/",target="/management-connector" fmc-build /bin/bash

or

docker run -it --mount type=bind,source="$(pwd)/",target="/management-connector" fmc-build  ./build_and_upgrade.sh -c upgrade -t <TARGET> -w
```

#### Example Commands run in the fmc-build Docker container
```
# Running Unit tests
root@acdc32ee8df8:/management-connector# nosetests tests/managementconnector/

# Doing a Build of FMC debian
root@acdc32ee8df8:/management-connector# ./build_and_upgrade.sh -c build
```

### Fixing an Expressway
If a test failure or some local development work has left your Expressway in a bad state you can use the following
utility script to fix it. This will leverage config on the Expressway, and the test config yaml to retrieve and access
token, and deregister your Expressway. It also has some fallback manual steps that it will take to make sure your
Expressway is in full working order.

```
./build_and_upgrade.sh -c clean_exp -t <TARGET>
or
python tests_integration/utils/clean_expressway.py <TARGET>
```

### Pipeline
FMC's pipeline is driven mainly from the Jenkins file in this repo. The Dockerfile is also used to create a docker image, which is the base of the Jenkins image. 
Using the root Dockerfile we generate a jenkins agent image from the jenkins directory which is uploaded to `containers.cisco.com`. When uploading ensure that you run the docker login command using the api key you genereated on containers, __not your CEC password__.
This image from containers.cisco.com is then leveraged by Cisco Crate (Containers as a service - CaaS) which allow us to adhere to the SQBU - BYOS (bring your own slaves) policy.

#### Cisco Crate
A crate enviroment has been setup to contain all Hybrid Management related containers, this was a one time thing completed with the sign-up link below, for reference. This environment was created in conjunction with the `hybrid-services-management` AD group

A stack can be created in Cisco Crate by uploading a docker-compose.yml file, this file lives in the `jenkins/agent/` directory and will outline the machine nanes and ports in crate, which are then supplied to CCE, to create the corresponding jenkins agents.

* [Hybrid Management Stacks](https://console.ciscocrate.com/env/1a2816697/apps/stacks)
* [Crate - Wiki](https://engit.cisco.com/storage-and-compute/cisco-crate)
* [Crate Environment sign-up](https://signup.ciscocrate.com/order)

#### Building the Builder images and pushing to Containers
```
docker build -t fmc-builder .
cd jenkins/agent/
docker build -t fmc-builder-base-ssh-slave .
docker run fmc-builder-base-ssh-slave /bin/bash
docker ps -l 
docker login
docker commit <CONTAINER ID> containers.cisco.com/hybridmanagement/fmc-builder-base-ssh-slave
docker push containers.cisco.com/hybridmanagement/fmc-builder-base-ssh-slave
```

#### Pulling the new images onto Crate
Go to the [Hybrid Management](https://console.ciscocrate.com/env/1a2816697/apps/stacks) stack in Cisco Crate. Next to each agent there
is a dotted menu with the option to upgrade:
![Agent](docs/images/agent.png?raw=true)

Click the upgarde option and on the next screen check the _Always pull image before creating_ option. Ensure that ```Interactive and TTY``` is selected on the Commands tab. Click upgrade and wait for crate to work:
![Upgrade](docs/images/upgrade.png?raw=true)

Note that if after upgrade Jenkins reports the agents as offline you may need to manually start the ssh daemon on the nodes in Crate. The command you need to run on the console of each node in Crate is ```/usr/sbin/sshd -D```.


#### Containers
* [FMC - Jenkins Builder Docker image](containers.cisco.com/repository/hybridmanagement/fmc-builder-base-ssh-slave)

### Security
* Threat Model ID: [21796](https://wwwin-tb.cisco.com/www/threatBuilder.html?id=21796)
* Threat Model Doc: [EDCS-1496496](https://docs.cisco.com/share/page/site/nextgen-edcs/document-details?nodeRef=workspace://SpacesStore/f12dde6e-2b99-4f02-9634-399d7f2858d9)
* IP Central: https://ipcentral.cisco.com/ipcentral/jsp/ipcentral.jsp?component=ProjectView&entityId=126815985
* Static Analysis: pylint is automatically run during the build process. Any new static analysis findings will cause the build to fail.

### Other resources/links
* [Fusion Management Connector (FMC) wiki page](https://wiki.cisco.com/pages/viewpage.action?pageId=114228940)
