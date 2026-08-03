FROM node:alpine AS build-web

WORKDIR /build

COPY . .

RUN corepack enable
RUN corepack prepare pnpm@latest --activate
RUN pnpm install
RUN pnpm build



FROM golang:1.22-bookworm AS build-bundle

RUN \
    apt-get update; apt-get install -y git make llvm-15 clang-15; \
    apt-get clean autoclean && apt-get autoremove -y && rm -rf /var/lib/{apt,dpkg,cache,log}/

# build bundle process
ENV CGO_ENABLED=0
ENV CLANG=clang-15
ARG DAED_VERSION=self-build
ARG WING_BRANCH=main
ARG DAE_BRANCH=main

WORKDIR /build

COPY --from=build-web /build/apps/web/dist ./web

# Build against the requested branches instead of the revisions pinned by the submodules.
RUN git clone --depth=1 --branch="${WING_BRANCH}" https://github.com/daeuniverse/dae-wing.git ./wing && \
    rm -rf ./wing/dae-core && \
    git clone --depth=1 --branch="${DAE_BRANCH}" --recurse-submodules --shallow-submodules \
      https://github.com/daeuniverse/dae.git ./wing/dae-core

WORKDIR /build/wing

RUN make APPNAME=daed VERSION=$DAED_VERSION OUTPUT=daed WEB_DIST=/build/web/ bundle




FROM alpine

LABEL org.opencontainers.image.source=https://github.com/daeuniverse/daed

RUN mkdir -p /usr/local/share/daed/
RUN mkdir -p /etc/daed/
RUN wget -O /usr/local/share/daed/geoip.dat https://github.com/v2rayA/dist-v2ray-rules-dat/raw/master/geoip.dat; \
    wget -O /usr/local/share/daed/geosite.dat https://github.com/v2rayA/dist-v2ray-rules-dat/raw/master/geosite.dat
COPY --from=build-bundle /build/wing/daed /usr/local/bin

EXPOSE 2023

CMD ["daed", "run", "-c", "/etc/daed"]
