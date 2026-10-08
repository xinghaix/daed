#!/usr/bin/env bash
#
# Manually sync the vendored upstream sources (see UPSTREAM.md).
#
#   scripts/sync-upstream.sh            # dae-wing + dae main, plus the
#                                       # dae_bpf_headers / outbound revisions they pin
#   WING_REF=<ref> DAE_REF=<ref> scripts/sync-upstream.sh
#   SKIP_OUTBOUND=1 scripts/sync-upstream.sh   # keep third_party/outbound as is
#
# For every component the script fetches the previously vendored commit and the
# new one, then applies the upstream diff between them on top of the vendored
# directory with `git apply --3way`. Local patches (e.g. the WebSocket early-data
# support in third_party/outbound) are therefore kept; if upstream touched the
# same lines, conflict markers are left in the files for manual resolution.
# Nothing is committed: review the staged result, resolve conflicts, build, then commit.
#
# Compatible with the bash 3.2 shipped by macOS.
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
VERSIONS=third_party/VERSIONS
WING_REF=${WING_REF:-main}
DAE_REF=${DAE_REF:-main}
SKIP_OUTBOUND=${SKIP_OUTBOUND:-}
TMP_REFS=refs/sync-upstream
FAILED=""

die() { echo "error: $*" >&2; exit 1; }
log() { printf '\033[1m==> %s\033[0m\n' "$*"; }

if ! git diff --quiet || ! git diff --cached --quiet; then
	die "working tree or index is not clean; commit or stash your changes first"
fi

# field <name> <column>: read a column of third_party/VERSIONS (1=name 2=url 3=branch 4=commit 5=prefixes)
field() {
	awk -v n="$1" -v c="$2" '$1 == n { print $c; exit }' "$VERSIONS"
}

set_field() { # set_field <name> <column> <value>
	awk -v n="$1" -v c="$2" -v v="$3" '
		$1 == n { $c = v; printf "%-16s %-47s %-5s %s  %s\n", $1, $2, $3, $4, $5; next }
		{ print }
	' "$VERSIONS" >"$VERSIONS.tmp"
	mv "$VERSIONS.tmp" "$VERSIONS"
}

fetch() { # fetch <url> <ref-or-sha>... ; echoes nothing, objects land in the local object store
	local url=$1
	shift
	git fetch --quiet --no-tags "$url" "$@"
}

# resolve_ref <url> <ref>: print the commit sha of a branch/tag/sha on a remote
resolve_ref() {
	local url=$1 ref=$2
	if [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
		echo "$ref"
		return
	fi
	fetch "$url" "+$ref:$TMP_REFS/resolve" || fetch "$url" "+refs/tags/$ref:$TMP_REFS/resolve"
	git rev-parse "$TMP_REFS/resolve^{commit}"
	git update-ref -d "$TMP_REFS/resolve"
}

# resolve_abbrev <url> <abbrev-sha>: resolve a short sha (Go pseudo-version suffix) on a remote
resolve_abbrev() {
	local url=$1 abbrev=$2 sha
	if sha=$(git rev-parse --quiet --verify "$abbrev^{commit}" 2>/dev/null); then
		echo "$sha"
		return
	fi
	fetch "$url" "+refs/heads/*:$TMP_REFS/abbrev/*" "+refs/tags/*:$TMP_REFS/abbrev-tags/*"
	sha=$(git rev-parse --quiet --verify "$abbrev^{commit}" || true)
	git for-each-ref --format='%(refname)' "$TMP_REFS/" | while read -r r; do git update-ref -d "$r"; done
	[ -n "$sha" ] || die "cannot find commit $abbrev in $url"
	echo "$sha"
}

# outbound_replace <file>: print the outbound replace line of a go.mod
outbound_replace() {
	grep -E '^replace github.com/daeuniverse/outbound( v[^ ]+)? =>' "$1" || true
}

# point_outbound <go.mod> <line>: rewrite the outbound replace line of a go.mod
point_outbound() {
	local mod=$1 line=$2
	LINE="$line" perl -0pi -e '
		s{(// daed: [^\n]*\n)?^replace github\.com/daeuniverse/outbound( v[^ ]+)? =>[^\n]*}{$ENV{LINE}}m
	' "$mod"
	git add "$mod"
}

local_outbound_line() { # local_outbound_line <relative path to third_party/outbound>
	printf '// daed: use the outbound fork vendored in this repository (third_party/VERSIONS).\nreplace github.com/daeuniverse/outbound => %s' "$1"
}

# apply_upstream <name> <old> <new> <prefix>
# Apply upstream's <old>..<new> diff (without gitlinks) onto <prefix>.
apply_upstream() {
	local name=$1 old=$2 new=$3 prefix=$4 patch excludes="" p out rc
	for p in $(git ls-tree -r "$old" | awk '$2 == "commit" { print $4 }') \
		$(git ls-tree -r "$new" | awk '$2 == "commit" { print $4 }'); do
		excludes="$excludes :(exclude)$p"
	done
	patch=$(mktemp)
	# shellcheck disable=SC2086
	git diff --binary --full-index --no-renames "$old" "$new" -- . $excludes >"$patch"
	if [ ! -s "$patch" ]; then
		rm -f "$patch"
		return
	fi
	# Only show what needs attention (conflicts, errors).
	rc=0
	out=$(git apply --3way --binary --whitespace=nowarn --directory="$prefix" "$patch" 2>&1) || rc=$?
	printf '%s\n' "$out" | grep -v -e '^Falling back to direct application' -e '^Applied patch .* cleanly' -e '^$' || true
	if [ "$rc" != 0 ]; then
		FAILED="$FAILED $name($prefix)"
	fi
	rm -f "$patch"
}

# sync_component <name> <old> <new> [go.mod-to-keep-pointing-at-vendored-outbound relpath]
sync_component() {
	local name=$1 old=$2 new=$3 mod=${4:-} rel=${5:-} prefix upstream_line
	if [ "$old" = "$new" ]; then
		log "$name: already at ${new:0:12}"
		return
	fi
	log "$name: ${old:0:12} -> ${new:0:12}"
	git --no-pager log --oneline --no-decorate "$old..$new" 2>/dev/null | sed 's/^/    /' | head -50 || true
	if [ -n "$mod" ]; then
		# Temporarily restore upstream's own outbound replace so the diff applies cleanly.
		upstream_line=$(outbound_replace <(git show "$old:go.mod"))
		[ -n "$upstream_line" ] && point_outbound "$mod" "$upstream_line"
	fi
	for prefix in $(field "$name" 5 | tr ',' ' '); do
		apply_upstream "$name" "$old" "$new" "$prefix"
	done
	if [ -n "$mod" ]; then
		point_outbound "$mod" "$(local_outbound_line "$rel")"
	fi
	set_field "$name" 4 "$new"
}

# --- dae-wing ---
url=$(field dae-wing 2)
old=$(field dae-wing 4)
fetch "$url" "$old"
new=$(resolve_ref "$url" "$WING_REF")
fetch "$url" "$new"
sync_component dae-wing "$old" "$new" wing/go.mod ../third_party/outbound

# --- dae ---
url=$(field dae 2)
old=$(field dae 4)
fetch "$url" "$old"
new=$(resolve_ref "$url" "$DAE_REF")
fetch "$url" "$new"
dae_new=$new
sync_component dae "$old" "$new" wing/dae-core/go.mod ../../third_party/outbound

# --- dae_bpf_headers (the gitlinks pinned by dae) ---
url=$(field dae_bpf_headers 2)
old=$(field dae_bpf_headers 4)
new=$(git ls-tree "$dae_new" control/kern/headers | awk '{ print $3 }')
trace_new=$(git ls-tree "$dae_new" trace/kern/headers | awk '{ print $3 }')
[ -n "$new" ] || die "dae $dae_new has no control/kern/headers gitlink; update $VERSIONS by hand"
[ "$new" = "$trace_new" ] || die "dae pins different control/trace header commits ($new vs $trace_new); sync them by hand"
if [ "$old" != "$new" ]; then
	fetch "$url" "$old" "$new"
fi
sync_component dae_bpf_headers "$old" "$new"

# --- outbound (the replace in dae's go.mod) ---
if [ -n "$SKIP_OUTBOUND" ]; then
	log "outbound: skipped (SKIP_OUTBOUND=1)"
else
	old=$(field outbound 4)
	old_url=$(field outbound 2)
	line=$(outbound_replace <(git show "$dae_new:go.mod"))
	if [ -n "$line" ]; then
		target=$(echo "$line" | sed -E 's/.*=> *//')
	else
		target="github.com/daeuniverse/outbound $(git show "$dae_new:go.mod" | awk '$1 == "github.com/daeuniverse/outbound" { print $2; exit }')"
	fi
	mod_path=$(echo "$target" | awk '{ print $1 }')
	version=$(echo "$target" | awk '{ print $2 }')
	case "$mod_path" in
	github.com/*) url="https://$mod_path" ;;
	*) die "unsupported outbound module source: $target" ;;
	esac
	url=${OUTBOUND_URL:-$url}
	if [ -n "${OUTBOUND_REF:-}" ]; then
		new=$(resolve_ref "$url" "$OUTBOUND_REF")
	elif [[ "$version" =~ -([0-9a-f]{12})$ ]]; then
		new=$(resolve_abbrev "$url" "${BASH_REMATCH[1]}")
	else
		new=$(resolve_ref "$url" "refs/tags/$version")
	fi
	fetch "$old_url" "$old" 2>/dev/null || resolve_abbrev "$old_url" "$old" >/dev/null
	fetch "$url" "$new"
	set_field outbound 2 "$url"
	sync_component outbound "$old" "$new"
fi

git add "$VERSIONS"
echo
git --no-pager diff --cached --stat | tail -1
if [ -n "$FAILED" ]; then
	echo
	echo "Conflicts while applying:$FAILED"
	echo "Resolve the conflict markers (git diff --name-only --diff-filter=U), 'git add' the files,"
	echo "then build and commit."
	exit 1
fi
cat <<'MSG'

Done. Next steps:
  1. make daed  (or: cd wing && go build ./... ; run 'go mod tidy' in wing/ if Go asks for it)
  2. cd third_party/outbound && go test ./transport/ws/...
  3. git commit -m "chore: sync upstream dae-wing/dae"
MSG
