#!/bin/bash -ex

# Make sure a SSH server is installed; that's what Jenkins uses to contact the slave.
if hash apt-get 2>/dev/null; then
    # debian based
    apt-get update
    apt-get install -y openssh-server default-jre git
else
    # centos
    yum install -y openssh-server java
    rm -rf /var/lib/apt/lists/*
    source ${JENKINS_AGENT_HOME}/.env
fi