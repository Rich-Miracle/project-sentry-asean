FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# Tools needed for traffic generation and testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping netcat-openbsd tcpdump curl iptables\
    python3 python3-pip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Upload server testing
COPY tests/upload_server.py /tmp/upload_server.py
COPY tests/us-server-entry.sh /tmp/us-server-entry.sh


# Trust the mitmproxy CA (so TLS interception isn't rejected)
COPY compose/mitm-ca/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
RUN update-ca-certificates

RUN echo "postfix postfix/mailname string mail.sentry.local" | debconf-set-selections && \
    echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections && \
    apt-get update && apt-get install -y --no-install-recommends postfix ssl-cert && \
    rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
