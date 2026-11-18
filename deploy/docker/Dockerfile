# syntax=docker/dockerfile:1
#
# sp-portal container image: ServerPerch customer portal + licensing backend.
# Build context is the repository root:
#
#   docker build -f deploy/docker/Dockerfile -t sp-portal:dev .
#   # or: docker compose -f deploy/compose/docker-compose.yml build
#
# Stages: (1) web build (Vite -> internal/webui/dist), (2) static Go build
# embedding that dist, (3) slim Debian runtime, non-root user.

ARG NODE_IMAGE=node:24-trixie-slim
ARG GO_IMAGE=golang:1.26-trixie
ARG RUNTIME_IMAGE=debian:13-slim

# ---------------------------------------------------------------------------
# 1. Web UI
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY web/ ./
# vite.config.ts: build.outDir = '../internal/webui/dist'
RUN npm run build && test -f /src/internal/webui/dist/index.html

# ---------------------------------------------------------------------------
# 2. Go build (static, CGO disabled)
# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS build
WORKDIR /src
ENV GOWORK=off \
    CGO_ENABLED=0 \
    GOFLAGS=-buildvcs=false \
    GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=web /src/internal/webui/dist/ internal/webui/dist/
ARG SP_PORTAL_VERSION=dev
ARG SP_PORTAL_COMMIT=none
ARG SP_PORTAL_BUILD_DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    pkg=github.com/technofish-au/sp-portal/internal/version \
    && go build -trimpath \
        -ldflags "-s -w -X ${pkg}.Version=${SP_PORTAL_VERSION} -X ${pkg}.Commit=${SP_PORTAL_COMMIT} -X ${pkg}.Date=${SP_PORTAL_BUILD_DATE}" \
        -o /out/sp-portal ./cmd/sp-portal \
    && /out/sp-portal version

# ---------------------------------------------------------------------------
# 3. Runtime
# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE}
ARG SP_PORTAL_VERSION=dev
ARG SP_PORTAL_COMMIT=none
LABEL org.opencontainers.image.title="sp-portal" \
      org.opencontainers.image.description="ServerPerch customer portal: admin/customer API, licensing backend and web UI" \
      org.opencontainers.image.version="${SP_PORTAL_VERSION}" \
      org.opencontainers.image.revision="${SP_PORTAL_COMMIT}"

# ca-certificates: outbound TLS (Stripe webhooks, SMTP). mariadb-client:
# operator debugging inside the container.
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates mariadb-client \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 portal \
    && useradd --system --uid 10001 --gid portal --home-dir /var/lib/sp-portal --no-create-home \
        --shell /usr/sbin/nologin portal \
    && install -d -o portal -g portal -m 0750 /var/lib/sp-portal

COPY --from=build /out/sp-portal /usr/bin/sp-portal

# MariaDB transport is the unix socket by default (db_host switches to TCP).
# The socket is mounted from the MariaDB container/host at /run/mysqld.
ENV PORTAL_HTTP_ADDR=:8080 \
    PORTAL_DB_SOCKET=/run/mysqld/mysqld.sock \
    PORTAL_DB_NAME=portal \
    PORTAL_DB_USER=portal \
    PORTAL_STORAGE_DIR=/var/lib/sp-portal

WORKDIR /var/lib/sp-portal
VOLUME ["/var/lib/sp-portal"]
EXPOSE 8080
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["sp-portal", "healthcheck"]

ENTRYPOINT ["sp-portal"]
CMD ["serve"]
