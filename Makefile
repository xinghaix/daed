OUTPUT ?= daed
APPNAME ?= daed
VERSION ?= 0.0.0.unknown

.PHONY: submodules submodule sync-upstream

daed:

all: clean daed

clean:
	rm -rf dist && rm -rf apps/web/dist && rm -f daed

## Begin Vendored Sources
# dae-wing (wing/), dae (wing/dae-core/) and the outbound fork
# (third_party/outbound/) are vendored as plain files; see UPSTREAM.md.
# Kept as no-ops for scripts that still call them.
submodule submodules:
	@true

# Manually pull the latest upstream dae-wing/dae main into the vendored dirs.
# Override the refs with WING_REF=<ref> DAE_REF=<ref>; SKIP_OUTBOUND=1 keeps third_party/outbound.
sync-upstream:
	./scripts/sync-upstream.sh
## End Vendored Sources

## Begin Web
PFLAGS ?=
ifeq (,$(wildcard ./.git))
	PFLAGS += HUSKY=0
endif
dist: package.json pnpm-lock.yaml
	$(PFLAGS) pnpm i
	TURBO_TELEMETRY_DISABLED=1 DO_NOT_TRACK=1 pnpm build
	@if [ -d "apps/web/dist" ]; then \
		rm -rf dist; \
		cp -r apps/web/dist dist; \
	fi
## End Web

## Begin Bundle
DAE_WING_READY=wing/graphql/service/config/global/generated_resolver.go

$(DAE_WING_READY): wing
	cd wing && \
	$(MAKE) deps && \
	cd .. && \
	touch $@

daed: $(DAE_WING_READY) dist
	cd wing && \
	$(MAKE) OUTPUT=../$(OUTPUT) APPNAME=$(APPNAME) WEB_DIST=../dist VERSION=$(VERSION) bundle
## End Bundle
