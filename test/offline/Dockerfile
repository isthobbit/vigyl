# Image for the offline proof (.github/workflows/offline-proof.yml):
# jensec plus pinned, checksum-verified scanners.
#
#   docker build -f test/offline/Dockerfile -t jensec-offline .

FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/jensec ./cmd/jensec

FROM python:3.12-slim

ARG SEMGREP_VERSION=1.165.0
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG TRIVY_VERSION=0.72.0
ARG TRIVY_SHA256=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
ARG OSV_VERSION=2.4.0
ARG OSV_SHA256=15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

RUN set -eux; cd /tmp; \
    curl -sSfL -o gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    echo "${GITLEAKS_SHA256}  gitleaks.tgz" | sha256sum -c -; \
    tar -xzf gitleaks.tgz -C /usr/local/bin gitleaks; \
    curl -sSfL -o trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    echo "${TRIVY_SHA256}  trivy.tgz" | sha256sum -c -; \
    tar -xzf trivy.tgz -C /usr/local/bin trivy; \
    curl -sSfL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64"; \
    echo "${OSV_SHA256}  /usr/local/bin/osv-scanner" | sha256sum -c -; \
    chmod +x /usr/local/bin/osv-scanner; \
    rm -f /tmp/*.tgz

COPY --from=build /out/jensec /usr/local/bin/jensec
COPY test/offline/run.sh /usr/local/bin/offline-proof
RUN chmod +x /usr/local/bin/offline-proof
