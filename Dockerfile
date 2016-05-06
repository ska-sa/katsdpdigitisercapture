FROM sdp-docker-registry.kat.ac.za:5000/docker-base

MAINTAINER Bruce Merry "bmerry@ska.ac.za"

# Install system packages
USER root
RUN apt-get -y update && apt-get --no-install-recommends -y install \
    tcpdump libpcap-dev libtbb-dev libboost-program-options1.55-dev hwloc-nox
USER kat

# Install dependencies for the script
RUN pip install netifaces==0.10.4

# Check out and build spead2
RUN mkdir -p /tmp/install/digitiser_decode && \
    cd /tmp/install && \
    git clone --single-branch --branch v0.8.0 --depth 1 https://github.com/ska-sa/spead2 && \
    make -j8 -C spead2/src libspead2.a

# Compile digitiser_decode
COPY . /tmp/install/digitiser_decode
RUN make -C /tmp/install/digitiser_decode SPEAD2_DIR=../spead2

# Install
USER root
RUN cp /tmp/install/digitiser_decode/digitiser_decode /tmp/install/digitiser_decode/digitiser_capture.py /usr/local/bin
