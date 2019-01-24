FROM sdp-docker-registry.kat.ac.za:5000/docker-base-build as build
MAINTAINER Bruce Merry "bmerry@ska.ac.za"

# Install build dependencies
USER root
RUN apt-get -y update && apt-get --no-install-recommends -y install \
        libpcap-dev libtbb-dev libboost-program-options-dev \
        autoconf automake
USER kat

# Check out and build spead2
RUN mkdir -p /tmp/install
WORKDIR /tmp/install
RUN git clone --single-branch --branch v1.11.2 --depth 1 https://github.com/ska-sa/spead2
WORKDIR /tmp/install/spead2
RUN mkdir build
RUN ./bootstrap.sh --no-python
WORKDIR /tmp/install/spead2/build
RUN ../configure --with-ibv --enable-lto AR=gcc-ar RANLIB=gcc-ranlib
RUN make -j8
USER root
RUN make -C /tmp/install/spead2/build install
# Install in a separate directory for copying to the runtime image
RUN make -C /tmp/install/spead2/build DESTDIR=/tmp/install/spead2-install install
USER kat

# Install Python dependencies
ENV PATH="$PATH_PYTHON3" VIRTUAL_ENV="$VIRTUAL_ENV_PYTHON3"
COPY requirements.txt /tmp/install/requirements.txt
RUN pip install -r /tmp/install/requirements.txt

# Compile digitiser_decode
COPY --chown=kat:kat . /tmp/install/digitiser_decode
RUN make -C /tmp/install/digitiser_decode

#######################################################################

FROM sdp-docker-registry.kat.ac.za:5000/docker-base-runtime
MAINTAINER Bruce Merry "bmerry@ska.ac.za"

# Install run-time dependencies (netbase is needed because pcap looks up
# protocols in /etc/protocols).
USER root
RUN apt-get -y update && apt-get --no-install-recommends -y install \
        libpcap0.8 libtbb2 hwloc-nox netbase && \
    rm -rf /var/lib/apt/lists/*
USER kat

# Install
COPY --from=build /tmp/install/spead2-install /
COPY --from=build /tmp/install/digitiser_decode/digitiser_decode /tmp/install/digitiser_decode/digitiser_capture.py /usr/local/bin/
COPY --from=build --chown=kat:kat /home/kat/ve3 /home/kat/ve3
ENV PATH="$PATH_PYTHON3" VIRTUAL_ENV="$VIRTUAL_ENV_PYTHON3"
