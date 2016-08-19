FROM ubuntu:16.04

# Install Java
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C2518248EEA14886 \
  && echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu xenial main" >> /etc/apt/sources.list \
  && apt-get update \
  && echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends oracle-java8-installer \
  && rm -rf /var/lib/apt/lists/*

# Install Ident.io server
RUN apt-get update \
  && export DEBIAN_FRONTEND=noninteractive \
  && apt-get install -y --no-install-recommends ca-certificates \
  && update-ca-certificates --fresh \
  && apt-get install -y --no-install-recommends jq \
  && export IDENTIO_RELEASE_URL=`wget -qO- https://api.github.com/repos/identio/identio-server/releases/latest | jq -r ".assets[] | select(.name | test(\".tar.gz\")) | .browser_download_url"` \
  && export IDENTIO_FILENAME=`wget -qO- https://api.github.com/repos/identio/identio-server/releases/latest | jq -r ".assets[] | select(.name | test(\".tar.gz\")) | .name"` \
  && cd /opt \
  && wget $IDENTIO_RELEASE_URL \
  && tar -xvzf $IDENTIO_FILENAME \
  && rm -rf $IDENTIO_FILENAME \
  && apt-get remove -y --auto-remove ca-certificates jq \
  && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /

WORKDIR /opt/identio-server

ENTRYPOINT ["/entrypoint.sh"]
