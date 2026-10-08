# syntax=docker/dockerfile:1
# ATTENTION This part below is for publishing purpose only

ARG DAED_VERSION

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build

RUN \
    apt-get update && apt-get install -y make llvm clang && \
    command -v clang && command -v llvm-strip && \
    apt-get clean autoclean && apt-get autoremove -y && rm -rf /var/lib/{apt,dpkg,cache,log}/

# build bundle process
ENV CGO_ENABLED=0
ARG DAED_VERSION

WORKDIR /build

COPY ./apps/web/dist/ ./web/

# dae-wing, dae and the outbound fork are vendored in this repository (see UPSTREAM.md).
# Download Go modules in their own layer so source-only changes reuse it.
COPY wing/go.mod wing/go.sum ./wing/
COPY wing/dae-core/go.mod wing/dae-core/go.sum ./wing/dae-core/
COPY third_party/outbound/go.mod third_party/outbound/go.sum ./third_party/outbound/
RUN cd wing && go mod download

COPY third_party ./third_party
COPY wing ./wing

WORKDIR /build/wing

# Cross-compile on the build host instead of emulating every target platform with QEMU.
ARG TARGETOS
ARG TARGETARCH
RUN GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    make APPNAME=daed VERSION=$DAED_VERSION OUTPUT=daed WEB_DIST=/build/web/ bundle


FROM --platform=$BUILDPLATFORM alpine AS geodata

RUN mkdir -p /geodata && \
    for name in geoip geosite; do \
      for i in 1 2 3 4 5; do \
        wget -O "/geodata/${name}.dat" "https://github.com/v2rayA/dist-v2ray-rules-dat/raw/master/${name}.dat" && break; \
        [ "$i" = 5 ] && exit 1; sleep 5; \
      done; \
    done


FROM alpine AS prod

LABEL org.opencontainers.image.source=https://github.com/daeuniverse/daed

RUN mkdir -p /etc/daed/
COPY --from=geodata /geodata/ /usr/local/share/daed/
COPY --from=build /build/wing/daed /usr/local/bin

EXPOSE 2023

CMD ["daed", "run", "-c", "/etc/daed"]
