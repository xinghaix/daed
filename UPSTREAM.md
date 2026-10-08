# Vendored upstream sources

daed builds entirely from sources tracked in this repository. There are no git
submodules and the build never clones upstream repositories.

| Directory                                                                  | Upstream                                                                      | Notes                                     |
| -------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------- |
| `wing/`                                                                    | [daeuniverse/dae-wing](https://github.com/daeuniverse/dae-wing) `main`        | backend (API + bundled web UI)            |
| `wing/dae-core/`                                                           | [daeuniverse/dae](https://github.com/daeuniverse/dae) `main`                  | proxy core                                |
| `wing/dae-core/control/kern/headers/`, `wing/dae-core/trace/kern/headers/` | [daeuniverse/dae_bpf_headers](https://github.com/daeuniverse/dae_bpf_headers) | revision pinned by dae's gitlinks         |
| `third_party/outbound/`                                                    | [olicesx/outbound](https://github.com/olicesx/outbound)                       | revision pinned by dae's `go.mod` replace |

The exact upstream commits are recorded in [`third_party/VERSIONS`](third_party/VERSIONS).

## Local patches

Keep local changes small and list them here so they are easy to re-check after a sync.

- `wing/go.mod`, `wing/dae-core/go.mod`: `replace github.com/daeuniverse/outbound`
  points at `third_party/outbound` instead of the upstream pseudo-version.
- `wing/dae-core/Makefile`: the submodule rule only runs `git submodule update`
  when the BPF header directories are empty (they are vendored).
- `third_party/outbound`: Xray-compatible WebSocket early data (`?ed=2048` in the
  ws path, optional `eh=` header name) for trojan/vless/vmess over ws
  (`transport/ws/earlydata.go`, `dialer/trojan/trojan.go`, `dialer/v2ray/v2ray.go`).

## Syncing with upstream (manual)

Upstream changes are pulled in by hand when wanted:

```bash
git checkout main && git pull
make sync-upstream            # or: ./scripts/sync-upstream.sh
```

Options (environment variables):

- `WING_REF=<branch|tag|sha>` / `DAE_REF=<branch|tag|sha>`: sync to something other than `main`.
- `SKIP_OUTBOUND=1`: leave `third_party/outbound` untouched.
- `OUTBOUND_URL=<git url>` / `OUTBOUND_REF=<ref>`: override the outbound source
  (by default it follows the `replace` in dae's `go.mod`).

For each component the script fetches the previously vendored commit and the new
one, and applies the upstream diff between them to the vendored directory with
`git apply --3way`, so local patches survive. The dae_bpf_headers and outbound
revisions follow whatever the new dae commit pins. `third_party/VERSIONS` is
updated and everything is left staged but **not committed**.

If upstream changed the same lines as a local patch, the script reports the
conflicts and leaves conflict markers. Resolve them (`git diff --name-only
--diff-filter=U`), `git add` the files, then verify and commit:

```bash
make daed VERSION=dev                      # or: cd wing && go build ./...
(cd third_party/outbound && go test ./transport/ws/...)
git commit -m "chore: sync upstream dae-wing/dae"
```

If Go reports that `go.mod` needs updating after a sync (dae-wing lagging behind
dae), run `go mod tidy` in `wing/` and commit the result.
