FROM --platform=$BUILDPLATFORM node:alpine AS build-web

WORKDIR /build

COPY . .

RUN npm install --global pnpm@10.24.0
RUN pnpm install
RUN pnpm build



FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build-bundle

RUN \
    apt-get update && apt-get install -y git make llvm clang && \
    command -v clang && command -v llvm-strip && \
    apt-get clean autoclean && apt-get autoremove -y && rm -rf /var/lib/{apt,dpkg,cache,log}/

# build bundle process
ENV CGO_ENABLED=0
ENV CLANG=clang
ARG DAED_VERSION=self-build
ARG WING_BRANCH=main
ARG DAE_BRANCH=main

WORKDIR /build

COPY --from=build-web /build/apps/web/dist ./web

# Build against the requested branches instead of the revisions pinned by the submodules.
# CI passes the resolved commits as WING_SHA/DAE_SHA so a cached clone is never reused after a branch moves.
ARG WING_SHA=
ARG DAE_SHA=
RUN git clone --depth=1 --branch="${WING_BRANCH}" https://github.com/daeuniverse/dae-wing.git ./wing && \
    if [ -n "${WING_SHA}" ]; then \
      git -C ./wing fetch --depth=1 origin "${WING_SHA}" && git -C ./wing checkout -q "${WING_SHA}"; \
    fi && \
    rm -rf ./wing/dae-core && \
    git clone --depth=1 --branch="${DAE_BRANCH}" https://github.com/daeuniverse/dae.git ./wing/dae-core && \
    if [ -n "${DAE_SHA}" ]; then \
      git -C ./wing/dae-core fetch --depth=1 origin "${DAE_SHA}" && git -C ./wing/dae-core checkout -q "${DAE_SHA}"; \
    fi && \
    git -C ./wing/dae-core submodule update --init --recursive --depth=1 && \
    echo "dae-wing $(git -C ./wing rev-parse --short HEAD), dae $(git -C ./wing/dae-core rev-parse --short HEAD)"

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


FROM alpine

LABEL org.opencontainers.image.source=https://github.com/daeuniverse/daed

RUN mkdir -p /etc/daed/
COPY --from=geodata /geodata/ /usr/local/share/daed/
COPY --from=build-bundle /build/wing/daed /usr/local/bin

EXPOSE 2023

CMD ["daed", "run", "-c", "/etc/daed"]
