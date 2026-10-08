OUTPUT ?= daed
APPNAME ?= daed
VERSION ?= 0.0.0.unknown

.PHONY: submodules submodule

daed:

all: clean daed

clean:
	rm -rf dist && rm -rf apps/web/dist && rm -f daed

## Begin Git Submodules
.gitmodules.d.mk: .gitmodules Makefile
	@set -e && \
	submodules=$$(grep '\[submodule "' .gitmodules | cut -d'"' -f2 | tr '\n' ' ' | tr ' \n' '\n' | sed 's/$$/\/.git/g') && \
	echo "submodule_ready=$${submodules}" > $@

-include .gitmodules.d.mk

$(submodule_ready): .gitmodules.d.mk
ifdef SKIP_SUBMODULES
	@echo "Skipping submodule update"
else
	git submodule update --init --recursive -- "$$(dirname $@)" && \
	touch $@
endif

submodule submodules: $(submodule_ready)
	@if [ -z "$(submodule_ready)" ]; then \
		rm -f .gitmodules.d.mk; \
		echo "Failed to generate submodules list. Please try again."; \
		exit 1; \
	fi
## End Git Submodules

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

## Begin Upstream Branches
# By default, build against the latest upstream branches of dae-wing and dae
# instead of the revisions pinned by the submodules.
# Set USE_PINNED_SUBMODULES=1 to build the pinned revisions instead.
WING_BRANCH ?= main
DAE_BRANCH ?= main

.PHONY: upstream-branches
upstream-branches: submodule
ifeq (,$(or $(SKIP_SUBMODULES),$(USE_PINNED_SUBMODULES)))
	@set -e; \
	before=$$(git -C wing rev-parse HEAD)-$$(git -C wing/dae-core rev-parse HEAD 2>/dev/null || true); \
	git -C wing fetch --depth=1 origin "$(WING_BRANCH)" && git -C wing checkout -q --detach FETCH_HEAD; \
	git -C wing submodule update --init --depth=1 dae-core; \
	git -C wing/dae-core fetch --depth=1 origin "$(DAE_BRANCH)" && git -C wing/dae-core checkout -q --detach FETCH_HEAD; \
	git -C wing/dae-core submodule update --init --recursive --depth=1; \
	after=$$(git -C wing rev-parse HEAD)-$$(git -C wing/dae-core rev-parse HEAD); \
	echo "dae-wing $(WING_BRANCH): $$(git -C wing rev-parse --short HEAD), dae $(DAE_BRANCH): $$(git -C wing/dae-core rev-parse --short HEAD)"; \
	if [ "$$before" != "$$after" ]; then rm -f $(DAE_WING_READY); fi
else
	@echo "Using pinned submodule revisions"
endif
## End Upstream Branches

$(DAE_WING_READY): wing
	cd wing && \
	$(MAKE) deps && \
	cd .. && \
	touch $@

daed: submodule upstream-branches $(DAE_WING_READY) dist
	cd wing && \
	$(MAKE) OUTPUT=../$(OUTPUT) APPNAME=$(APPNAME) WEB_DIST=../dist VERSION=$(VERSION) bundle
## End Bundle
