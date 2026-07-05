FROM golang:1.26-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b AS go-tools

ARG SUBFINDER_VERSION=v2.14.0
ARG HTTPX_VERSION=v1.9.0
ARG NAABU_VERSION=v2.6.1
ARG NUCLEI_VERSION=v3.10.0
ARG AMASS_VERSION=v5.1.1

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}
RUN go install github.com/owasp-amass/amass/v5/cmd/amass@${AMASS_VERSION}

FROM ghcr.io/zaproxy/zaproxy:stable@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2

USER root

ARG TESTSSL_REF=9fdf8028baba86d83218db294a5776384ec8c332
ARG NUCLEI_TEMPLATES_REF=dee7c015cf20e347097af5e139acf0d5d18af77b
ARG INTERNETNL_REF=9d468751401d4217a986ddbb100d6f7db33769ed
ARG GVM_TOOLS_VERSION=26.0.6
ARG GREENBONE_FEED_SYNC_VERSION=25.3.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    bsdextrautils \
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

RUN git init /opt/testssl.sh \
    && git -C /opt/testssl.sh remote add origin https://github.com/testssl/testssl.sh \
    && git -C /opt/testssl.sh fetch --depth=1 origin "${TESTSSL_REF}" \
    && git -C /opt/testssl.sh checkout --detach FETCH_HEAD \
    && rm -rf /opt/testssl.sh/.git \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
RUN git init /opt/nuclei-templates \
    && git -C /opt/nuclei-templates remote add origin https://github.com/projectdiscovery/nuclei-templates \
    && git -C /opt/nuclei-templates fetch --depth=1 origin "${NUCLEI_TEMPLATES_REF}" \
    && git -C /opt/nuclei-templates checkout --detach FETCH_HEAD \
    && rm -rf /opt/nuclei-templates/.git
RUN git init /opt/internetnl \
    && git -C /opt/internetnl remote add origin https://github.com/internetstandards/Internet.nl \
    && git -C /opt/internetnl fetch --depth=1 origin "${INTERNETNL_REF}" \
    && git -C /opt/internetnl checkout --detach FETCH_HEAD \
    && rm -rf /opt/internetnl/.git
RUN python3 -m pip install --break-system-packages --no-cache-dir \
    gvm-tools==${GVM_TOOLS_VERSION} \
    greenbone-feed-sync==${GREENBONE_FEED_SYNC_VERSION} || true

COPY --from=go-tools /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-tools /go/bin/httpx /usr/local/bin/httpx
COPY --from=go-tools /go/bin/naabu /usr/local/bin/naabu
COPY --from=go-tools /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=go-tools /go/bin/amass /usr/local/bin/amass

COPY docker/tools/domain-score-tools /usr/local/bin/domain-score-tools
RUN chmod +x /usr/local/bin/domain-score-tools

ENV HOME=/tmp
WORKDIR /tmp
ENTRYPOINT ["domain-score-tools"]
