FROM python:2.7.15

# Install gettext for msgfmt localisation tool
RUN apt-get update && apt-get install -y \
    gettext

ADD . /management-connector
WORKDIR /management-connector
VOLUME /management-connector
CMD [ "./build.sh" ]