ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG DEBIAN_SNAPSHOT
ARG SECURITY_SNAPSHOT
# Debian authenticates frozen repository metadata and packages. HTTP bootstraps
# the CA bundle; discovery performs no runtime downloads.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources \
 && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s trixie main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s trixie-security main\n' "$DEBIAN_SNAPSHOT" "$SECURITY_SNAPSHOT" > /etc/apt/sources.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY bin/ /usr/bin/
COPY licenses/ /usr/share/doc/discovery-bridge/licenses/
COPY metadata.json /usr/share/doc/discovery-bridge/build.json
COPY SHA256SUMS /tmp/discovery-bridge.SHA256SUMS
RUN cd /usr/bin && sha256sum --strict --check /tmp/discovery-bridge.SHA256SUMS \
 && rm /tmp/discovery-bridge.SHA256SUMS \
 && chmod 0555 discovery-bridge kubectl crictl \
 && discovery-bridge version && kubectl version --client=true && crictl --version && ip -Version
ENV GOMAXPROCS=2
USER 65532:65532
ENTRYPOINT ["/usr/bin/discovery-bridge"]
CMD ["version"]
