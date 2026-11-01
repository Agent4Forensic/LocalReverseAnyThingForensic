# sw-analyst tool images (ADR-0006, package B). Build with infra\tools\build-images.ps1, never by hand with other tags.
# Every download and base image is pinned; sha256sum -c fails the build on any mismatch. Network is needed only here, at
# build time: the containers themselves always run with --network none (src/sw_analyst/gateway/container_runner.py).
# REA and MCP servers are deliberately absent (ADR-0006: REA deferred, the MCP protocol is not passed through).
#   docker build --target ghidra -t sw-analyst/ghidra:12.1.4 infra/tools
#   docker build --target triage -t sw-analyst/triage:1 infra/tools
#   docker build --target jadx   -t sw-analyst/jadx:1.5.6 infra/tools

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS fetch
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*

FROM fetch AS fetch-ghidra
RUN curl -fsSL -o /g.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip \
 && echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  /g.zip" | sha256sum -c - \
 && unzip -q /g.zip -d /opt && mv /opt/ghidra_12.1.4_PUBLIC /opt/ghidra && rm -rf /g.zip /opt/ghidra/docs

FROM fetch AS fetch-triage
RUN mkdir -p /opt/tools /d \
 && curl -fsSL -o /d/capa.zip https://github.com/mandiant/capa/releases/download/v10.0.0/capa-v10.0.0-linux.zip \
 && echo "96cb5115f495024a478b0e9f9f77f9027058155589235fbd4c50e7382055fcca  /d/capa.zip" | sha256sum -c - \
 && curl -fsSL -o /d/floss.zip https://github.com/mandiant/flare-floss/releases/download/v3.2.0/floss-v3.2.0-linux.zip \
 && echo "c449366960b688769b6510662cd6db6a3bf9edada4e8a8878056becd324df52c  /d/floss.zip" | sha256sum -c - \
 && curl -fsSL -o /d/yr.tgz https://github.com/VirusTotal/yara-x/releases/download/v1.22.1/yara-x-v1.22.1-x86_64-unknown-linux-gnu.tar.gz \
 && echo "c0ff80408d57b94f8348b9b19b5c70fb03e6471e7fdd761c97e0b4876804eecf  /d/yr.tgz" | sha256sum -c - \
 && unzip -q /d/capa.zip -d /opt/tools && unzip -q /d/floss.zip -d /opt/tools && tar -xzf /d/yr.tgz -C /opt/tools \
 && chmod 0755 /opt/tools/capa /opt/tools/floss /opt/tools/yr

FROM fetch AS fetch-jadx
RUN curl -fsSL -o /j.zip https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip \
 && echo "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974  /j.zip" | sha256sum -c - \
 && unzip -q /j.zip -d /opt/jadx && chmod 0755 /opt/jadx/bin/jadx && rm /j.zip

FROM eclipse-temurin:21-jdk-noble@sha256:bd6ac06e2a2df928af21c75c4a8a0f2829a93377a65761d6a577bb32281e2ac3 AS ghidra
COPY --from=fetch-ghidra /opt/ghidra /opt/ghidra
COPY entry.sh ghidra/ExportAll.java /opt/sw/
RUN chmod 0555 /opt/sw/entry.sh && sed -i 's/^MAXMEM=.*/MAXMEM=4G/; s/^#MAXMEM=.*/MAXMEM=4G/' /opt/ghidra/support/analyzeHeadless
ENV HOME=/tmp
USER 10001:10001
ENTRYPOINT ["/opt/sw/entry.sh"]

FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852 AS triage
COPY --from=fetch-triage /opt/tools /opt/tools
RUN echo "analyst:x:10001:10001::/tmp:/usr/sbin/nologin" >> /etc/passwd
COPY entry.sh rules/sw_analyst.yar /opt/sw/
RUN chmod 0555 /opt/sw/entry.sh
ENV HOME=/tmp
USER 10001:10001
ENTRYPOINT ["/opt/sw/entry.sh"]

FROM eclipse-temurin:21-jre-noble@sha256:161310cd5bd41fd549d19cf9f90b614897cb4a1532555c613b43b7e0628fe5d6 AS jadx
COPY --from=fetch-jadx /opt/jadx /opt/jadx
COPY entry.sh /opt/sw/
RUN chmod 0555 /opt/sw/entry.sh
ENV HOME=/tmp JAVA_OPTS=-Xmx3g
USER 10001:10001
ENTRYPOINT ["/opt/sw/entry.sh"]
