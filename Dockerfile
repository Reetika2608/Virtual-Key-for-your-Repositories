FROM python:2.7.17

# Install gettext for msgfmt localisation tool
RUN apt-get update && apt-get install -y \
    gettext sshpass

# Install Chrome
RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN dpkg -i google-chrome-stable_current_amd64.deb; apt-get -fy install

# Installing test requirements, which will be cached as a layer
COPY test_environment/requirements.txt test-requirements
RUN pip install -r test-requirements

WORKDIR /management-connector
