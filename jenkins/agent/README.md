# Jenkins Agent

To create a jenkins compatible docker container which will be used in the pipeline to build FMC, we need to wrap our fmc-builder image.

## Generating SSH keys for agent
Generate a ssh key pair, embed the public key in the ssh docker image, and supply the private key to CCE when adding the agent to the Jenkins server.

`ssh-keygen -t rsa -b 4096 -f id_rsa`

From here take the public key and add it to the `JENKINS_SLAVE_SSH_PUBKEY_DEFAULT` var in the .env file, so it can be injected in the agent docker image.

## Building the Jenkins Agent Image
docker build -t connector-build-base-ssh-slave .

## Running a local instance of Jenkins
docker run -p 8080:8080 -p 50000:50000 -v /your/home:/var/jenkins_home jenkins
