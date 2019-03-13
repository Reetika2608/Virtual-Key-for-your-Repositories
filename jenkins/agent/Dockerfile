#######
# Basic Jenkins SSH Slave, based from fmc-builder, created from root Dockerfile
# and pushed to containers.cisco.com/hybridmanagement/fmc-builder-base-ssh-slave
# Copied from debian example here
# https://github.com/jenkinsci/docker-ssh-slave/blob/master/Dockerfile
#######

FROM fmc-builder:latest
MAINTAINER Hybrid Management <expressway-gwy-1@cisco.com>

ARG user=jenkins
ARG group=jenkins
ARG uid=1000
ARG gid=1000
ARG JENKINS_AGENT_HOME=/home/${user}

ENV JENKINS_AGENT_HOME ${JENKINS_AGENT_HOME}

RUN groupadd -g ${gid} ${group} \
    && useradd -d "${JENKINS_AGENT_HOME}" -u "${uid}" -g "${gid}" -m -s /bin/bash "${user}"

# Set default SSH pub key
COPY .env ${JENKINS_AGENT_HOME}/.env

# setup SSH server & java
COPY slave-stuff.sh /tmp/slave-stuff.sh
RUN cd /tmp \
    && bash slave-stuff.sh \
    && rm /tmp/slave-stuff.sh

RUN sed -i /etc/ssh/sshd_config \
        -e 's/#PermitRootLogin.*/PermitRootLogin no/' \
        -e 's/#RSAAuthentication.*/RSAAuthentication yes/'  \
        -e 's/#PasswordAuthentication.*/PasswordAuthentication no/' \
        -e 's/#SyslogFacility.*/SyslogFacility AUTH/' \
        -e 's/#LogLevel.*/LogLevel INFO/' && \
    mkdir /var/run/sshd

VOLUME "${JENKINS_AGENT_HOME}" "/tmp" "/run" "/var/run"
WORKDIR "${JENKINS_AGENT_HOME}"

COPY setup-sshd /usr/local/bin/setup-sshd
RUN chmod 777 /usr/local/bin/setup-sshd

EXPOSE 22

ENTRYPOINT ["setup-sshd"]
