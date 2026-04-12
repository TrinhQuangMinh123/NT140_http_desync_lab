FROM ubuntu:20.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies for ATS 9.2.0
RUN apt-get update && apt-get install -y \
    wget \
    build-essential \
    libssl-dev \
    libpcre3-dev \
    libcap-dev \
    libhwloc-dev \
    libncurses5-dev \
    libcurl4-openssl-dev \
    flex \
    autoconf \
    automake \
    libtool \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Download and install Apache Traffic Server 9.2.0 (specific version, no upgrade)
WORKDIR /tmp
RUN wget https://archive.apache.org/dist/trafficserver/trafficserver-9.2.0.tar.bz2 && \
    tar xjf trafficserver-9.2.0.tar.bz2 && \
    cd trafficserver-9.2.0 && \
    ./configure --prefix=/opt/ats && \
    make && \
    make install && \
    cd .. && \
    rm -rf trafficserver-9.2.0 trafficserver-9.2.0.tar.bz2

# Copy configuration files
COPY records.config /opt/ats/etc/trafficserver/records.config
COPY remap.config /opt/ats/etc/trafficserver/remap.config

# Expose port 80 (internal)
EXPOSE 80

# Start ATS
CMD ["/opt/ats/bin/traffic_server"]
