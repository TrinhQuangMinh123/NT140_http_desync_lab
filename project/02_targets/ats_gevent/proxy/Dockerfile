FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y trafficserver && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/trafficserver && chown -R trafficserver:trafficserver /run/trafficserver
CMD traffic_server --bind_stdout --bind_stderr
