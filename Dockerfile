# syntax=docker/dockerfile:1
#
# Open MCP Portal image (docs/deploy.md).
#
#   make docker                                  # open-mcp-portal:<version>
#   docker build --target fakemcp -t omp-fakemcp .   # the fake MCP server (demo only)
#
# Multi-arch build: the web UI and the Go binary are built on the build
# platform and cross-compiled for the target (no emulation for the slow
# steps). The UI is embedded in the binary (web/embed.go).
#
# Every base image is pinned by the digest of its multi-arch index, with the
# tag kept for people to read. Dependabot's docker ecosystem (.github/
# dependabot.yml) opens one pull request a week that moves the digests; to
# resolve one by hand: docker buildx imagetools inspect <image:tag>.

FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts
COPY web/ ./
# The type-check covers src/test, which reads ../api/openapi.yaml.
COPY api/ /api/
RUN npm run build && test -f dist/index.html

FROM --platform=$BUILDPLATFORM golang:1.26.10@sha256:c141012f2b79382f9cb7438104ae0cd324cc548c1a605f393ef7402b87a1bd8b AS gobase
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}

FROM gobase AS build
COPY --from=web /web/dist ./web/dist
ARG VERSION=dev
ARG COMMIT=unknown
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath \
    -ldflags "-s -w -X github.com/ncecere/open-mcp-portal/internal/buildinfo.Version=${VERSION} -X github.com/ncecere/open-mcp-portal/internal/buildinfo.Commit=${COMMIT}" \
    -o /out/open-mcp-portal ./cmd/open-mcp-portal

# The fake MCP server (cmd/fakemcp), for compose.demo.yaml only. Built only
# when this target (or the demo) asks for it.
FROM gobase AS build-fakemcp
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w" -o /out/fakemcp ./cmd/fakemcp

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS fakemcp
COPY --from=build-fakemcp /out/fakemcp /fakemcp
USER 65532:65532
ENTRYPOINT ["/fakemcp"]

# The portal (default target). Distroless: no shell or package manager;
# runs as a non-root user (65532) and works with a read-only root
# filesystem. There is no HEALTHCHECK (no shell or curl in the image):
# Kubernetes probes /healthz (liveness, startup) and /readyz (readiness).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=dev
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="open-mcp-portal" \
      org.opencontainers.image.description="Open MCP Portal: a self-hosted portal for governed access to a company's MCP servers" \
      org.opencontainers.image.source="https://github.com/ncecere/open-mcp-portal" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
COPY --from=build /out/open-mcp-portal /open-mcp-portal
USER 65532:65532
EXPOSE 8088
ENTRYPOINT ["/open-mcp-portal"]
CMD ["serve"]
