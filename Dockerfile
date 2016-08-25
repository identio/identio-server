FROM ubuntu:16.04

# Add the sources to the application
ADD . /tmp/identio-server-build

# Prepare system and install Java
RUN groupadd -r identio && useradd -r -g identio identio \
	&& apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C2518248EEA14886 \
	&& echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu xenial main" >> /etc/apt/sources.list \
	&& apt-get update \
	&& echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends oracle-java8-installer \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bzip2 git \	
	&& cd /tmp/identio-server-build \
	&& ./gradlew releaseTarGz \
	&& cd /opt \
	&& tar -xzvf /tmp/identio-server-build/build/distributions/identio-server.tar.gz \
	&& cp /tmp/identio-server-build/docker/entrypoint.sh / \
	&& rm -rf /tmp/identio-server-build \
	&& apt-get remove -y --auto-remove bzip2 git \
	&& rm -rf /var/lib/apt/lists/* \
	&& chown -R identio:identio /opt/identio/config/work

USER identio
 
WORKDIR /opt/identio-server

ENTRYPOINT ["/entrypoint.sh"]
