FROM python:2.7.15

# Install gettext for msgfmt localisation tool
RUN apt-get update && apt-get install -y \
    gettext

# Installing test requirements, which will be cached as a layer
COPY test_environment/requirements.txt test-requirements
RUN pip install -r test-requirements

ADD . /management-connector
WORKDIR /management-connector
