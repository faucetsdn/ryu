FROM ubuntu:16.04

MAINTAINER IWASE Yusuke <iwase.yusuke0@gmail.com>

USER root
WORKDIR /root

COPY ENTRYPOINT.sh /

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    mininet \
    net-tools \
 && rm -rf /var/lib/apt/lists/* \
 && sed -i -e "s/datapath='kernel'/datapath='user'/" \
        /usr/lib/python2.7/dist-packages/mininet/node.py \
 && chmod +x /ENTRYPOINT.sh

EXPOSE 6640

ENTRYPOINT ["/ENTRYPOINT.sh"]
