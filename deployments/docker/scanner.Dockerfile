# syntax=docker/dockerfile:1.7
#
# CRAB scanner image: the crab-risk-scan CLI with the pinned engines from engines.lock.json.
# Build from the repository root:
#
#   docker build -f deployments/docker/scanner.Dockerfile -t crab-risk-scan .
#
# Optional build arguments:
#   INSTALL_PWSH=true   add PowerShell so the psscriptanalyzer engine can run
#   PREFETCH_DB=true    run `crab-risk-scan db update` at build time so scans work offline
#
# The engines and databases are fetched only during the build. Scans run offline by default.

ARG PYTHON_IMAGE=python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

FROM ${PYTHON_IMAGE} AS build

ARG TARGETARCH
ARG INSTALL_PWSH=false
ARG PWSH_VERSION=7.6.10
ARG PWSH_SHA256_AMD64=e261cabc91c78a9afe8d1e5f24731ab0d38204735ab2ec94b0af55102652e10d
ARG PWSH_SHA256_ARM64=439432cdecf4418413b9a8f547e3ab4d9b40e8e4258913ec3d15fc92c67a9235
ARG PREFETCH_DB=false

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CRAB_CACHE_DIR=/opt/crab/cache

RUN apt-get update \
 && apt-get install --yes --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Install CRAB into its own virtual environment from the build context.
COPY . /src
RUN python -m venv /opt/crab/venv \
 && /opt/crab/venv/bin/pip install "/src[docx]"
ENV PATH=/opt/crab/venv/bin:$PATH

# Pinned engines with SHA-256 verification: binaries in /opt/crab/engines/bin, pip engines in
# /opt/crab/engines/venvs and the PSScriptAnalyzer module in /opt/crab/engines/modules.
RUN crab-risk-scan engines install --dest /opt/crab/engines

# PowerShell runtime for PSScriptAnalyzer, from the checksum-pinned release archive.
RUN mkdir -p /opt/microsoft/powershell \
 && if [ "$INSTALL_PWSH" = "true" ]; then \
      arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
      case "$arch" in \
        amd64) asset=x64; sum="$PWSH_SHA256_AMD64" ;; \
        arm64) asset=arm64; sum="$PWSH_SHA256_ARM64" ;; \
        *) echo "PowerShell is not available for $arch" >&2; exit 1 ;; \
      esac; \
      curl --fail --location --retry 3 --proto '=https' --tlsv1.2 -o /tmp/pwsh.tar.gz \
        "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-linux-${asset}.tar.gz"; \
      echo "${sum}  /tmp/pwsh.tar.gz" | sha256sum -c -; \
      tar -xzf /tmp/pwsh.tar.gz -C /opt/microsoft/powershell; \
      chmod 0755 /opt/microsoft/powershell/pwsh; \
      rm /tmp/pwsh.tar.gz; \
    fi

# Optional offline vulnerability databases for Trivy and OSV-Scanner.
RUN mkdir -p "$CRAB_CACHE_DIR" \
 && if [ "$PREFETCH_DB" = "true" ]; then crab-risk-scan db update --cache-dir "$CRAB_CACHE_DIR"; fi


FROM ${PYTHON_IMAGE}

ARG INSTALL_PWSH=false

LABEL org.opencontainers.image.title="crab-risk-scan" \
      org.opencontainers.image.description="CRAB offline-first repository security scanner with pinned engines" \
      org.opencontainers.image.licenses="Apache-2.0"

# git serves worker jobs with git sources. The ICU, OpenSSL and Kerberos libraries are the
# PowerShell runtime dependencies on Debian 13.
RUN apt-get update \
 && apt-get install --yes --no-install-recommends ca-certificates git \
 && if [ "$INSTALL_PWSH" = "true" ]; then \
      apt-get install --yes --no-install-recommends libicu76 libssl3t64 libgssapi-krb5-2; \
    fi \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 crab \
 && useradd --uid 10001 --gid 10001 --home-dir /home/crab --create-home --shell /usr/sbin/nologin crab

COPY --from=build /opt/crab/venv /opt/crab/venv
COPY --from=build /opt/crab/engines /opt/crab/engines
COPY --from=build /opt/microsoft/powershell /opt/microsoft/powershell
COPY --from=build --chown=10001:10001 /opt/crab/cache /opt/crab/cache

# CI runners often start the container with the host user's uid so results stay writable in the
# checkout. The engine databases therefore stay readable and writable for any uid.
RUN if [ "$INSTALL_PWSH" = "true" ]; then ln -s /opt/microsoft/powershell/pwsh /usr/local/bin/pwsh; fi \
 && chmod -R a+rwX /opt/crab/cache \
 && mkdir -p /work \
 && chown 10001:10001 /work

ENV PATH=/opt/crab/venv/bin:$PATH \
    CRAB_ENGINE_DIR=/opt/crab/engines/bin \
    CRAB_CACHE_DIR=/opt/crab/cache \
    HOME=/home/crab \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    POWERSHELL_UPDATECHECK=Off \
    DOTNET_CLI_TELEMETRY_OPTOUT=1

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["crab-risk-scan"]
CMD ["--help"]
