# wing/Dockerfile
FROM golang:1.26-bookworm AS builder

WORKDIR /build

RUN apt-get update
RUN apt-get install -y git make llvm-15 clang-15

ENV CGO_ENABLED=0
ENV CLANG=clang-15
ARG VERSION=self-build

COPY . .

RUN make APPNAME=dae-wing VERSION=$VERSION

FROM alpine

WORKDIR /etc/dae-wing

RUN set -e; \
    mkdir -p /usr/local/share/dae-wing; \
    download() { \
        dest="$1"; \
        url="$2"; \
        for attempt in 1 2 3 4 5; do \
            wget -T 30 -O "$dest" "$url" && return 0; \
            rm -f "$dest"; \
            sleep "$attempt"; \
        done; \
        return 1; \
    }; \
    download /usr/local/share/dae-wing/geoip.dat https://raw.githubusercontent.com/v2rayA/dist-v2ray-rules-dat/master/geoip.dat; \
    download /usr/local/share/dae-wing/geosite.dat https://raw.githubusercontent.com/v2rayA/dist-v2ray-rules-dat/master/geosite.dat
COPY --from=builder /build/dae-wing /usr/local/bin

EXPOSE 2023

CMD ["dae-wing"]
ENTRYPOINT ["dae-wing", "run", "-c", "."]
