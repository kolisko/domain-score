FROM golang:1.26-bookworm AS go-tools

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/owasp-amass/amass/v5/cmd/amass@latest

FROM ghcr.io/zaproxy/zaproxy:stable

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    dnsutils \
    git \
    jq \
    nmap \
    openssl \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-tools /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-tools /go/bin/httpx /usr/local/bin/httpx
COPY --from=go-tools /go/bin/naabu /usr/local/bin/naabu
COPY --from=go-tools /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=go-tools /go/bin/amass /usr/local/bin/amass

RUN git clone --depth=1 https://github.com/testssl/testssl.sh /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
RUN git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates /opt/nuclei-templates
RUN git clone --depth=1 https://github.com/internetstandards/Internet.nl /opt/internetnl
RUN python3 -m pip install --break-system-packages --no-cache-dir gvm-tools greenbone-feed-sync || true

COPY docker/tools/domain-score-tools /usr/local/bin/domain-score-tools
RUN chmod +x /usr/local/bin/domain-score-tools

ENV HOME=/tmp
WORKDIR /tmp
ENTRYPOINT ["domain-score-tools"]
