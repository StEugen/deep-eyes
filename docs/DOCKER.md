# Docker

Deep Eye can run in a least-privilege container without installing its Python dependencies on the host.

The Docker files deliberately do not start scans during image build or on a plain `docker compose up`. The default command is `--help`; an authorized target must be supplied explicitly.

## Files

- `Dockerfile` — non-root Python runtime with an optional Playwright target.
- `compose.yaml` — read-only root filesystem, dropped Linux capabilities, persistent named volumes, and a read-only configuration mount.
- `.dockerignore` — excludes local credentials, scan data, reports, databases, pickle files, Git metadata, and development artifacts from the build context.

## Prepare configuration

Create the local configuration before using Compose:

```bash
cp config/config.example.yaml config/config.yaml
chmod 600 config/config.yaml
```

Edit `config/config.yaml` and:

- enable only the AI provider you intend to use;
- keep `plugin_manager.enabled`, `templates.enabled`, `rag.enabled`, `intercepting_proxy.enabled`, and `oast.enabled` disabled unless specifically required and reviewed;
- set an explicit `scope` allowlist;
- use only targets covered by written authorization.

`config/config.yaml` is excluded from both Git and the Docker build context. Compose mounts it read-only at runtime.

## Build

Core image, without a bundled browser:

```bash
docker compose build deep-eye
```

Browser-capable image for Playwright features:

```bash
DEEP_EYE_DOCKER_TARGET=browser docker compose build deep-eye
```

The browser target is substantially larger because it installs Chromium and its system libraries. The core target is sufficient while `advanced.enable_javascript_rendering` and `challenge_solver.enabled` are false.

## Run an authorized scan

```bash
docker compose run --rm deep-eye \
  -u https://authorized-target.example \
  --no-banner
```

Pass additional CLI options after the service name:

```bash
docker compose run --rm deep-eye \
  -u https://authorized-target.example \
  --formats html,json \
  -v
```

A plain invocation is intentionally inert:

```bash
docker compose run --rm deep-eye
```

It displays help because the image defaults to `--help`.

## Secrets and environment substitution

Deep Eye supports `${VAR}` substitutions in `config/config.yaml`. Pass only the variables required by the selected provider:

```bash
docker compose run --rm \
  -e OPENAI_API_KEY \
  deep-eye \
  -u https://authorized-target.example
```

Then reference the variable in the mounted configuration:

```yaml
ai_providers:
  openai:
    enabled: true
    api_key: "${OPENAI_API_KEY}"
```

The variable is visible to the container process and Docker metadata. For higher-assurance environments, use an external secret manager to render a short-lived, permission-restricted `config/config.yaml` instead of placing long-lived keys in shell history or Compose files.

## Hermes/Codex connection

When Deep Eye is configured to use Hermes' OpenAI-compatible API server, a container cannot use host `127.0.0.1`; that address means the container itself. Use Docker's host alias:

```text
http://host.docker.internal:8642/v1
```

`compose.yaml` defines `host.docker.internal` for Docker Desktop and Linux engines that support the host-gateway mapping.

Keep these credential boundaries separate:

- Deep Eye receives only the Hermes API-server bearer key.
- Hermes owns and refreshes Codex/ChatGPT OAuth credentials.
- Do not mount `~/.hermes`, `~/.codex`, Docker socket, or the host home directory into the Deep Eye container.

Hermes binds its API server to loopback by default. Docker Desktop can normally route the host alias to host services; on other engines, a service listening only on host loopback may not be reachable. Do not solve that by casually binding Hermes to every interface. If remote/container access is required, use a dedicated restricted Hermes profile, a controlled bind address, firewall rules, and a strong unique API-server key.

## Persistent output

Compose stores runtime state in named volumes:

- `deep-eye-data`
- `deep-eye-logs`
- `deep-eye-reports`

Inspect or export them deliberately after a scan. They can contain credentials, target responses, tokens, and vulnerability evidence. Do not commit their contents.

Example report export:

```bash
cid=$(docker create -v deep-eye_deep-eye-reports:/reports alpine:3.20)
docker cp "$cid:/reports/." ./reports/
docker rm "$cid"
```

The exact Compose volume prefix can differ when `COMPOSE_PROJECT_NAME` is changed; inspect the volume name before exporting.

## Isolation choices

The default Compose service:

- runs as UID/GID `10001`;
- drops all Linux capabilities;
- enables `no-new-privileges`;
- uses a read-only root filesystem;
- provides a bounded shared-memory allocation for Chromium;
- provides bounded temporary filesystems for `/tmp` and the user cache;
- mounts configuration read-only;
- does not mount the Docker socket or host filesystem;
- does not publish ports;
- persists only data, logs, and reports.

Some optional Deep Eye modules conflict with that isolation:

- `intercepting_proxy` expects a `mitmweb` subprocess, which is not installed in the image;
- Frida/mobile testing requires USB/device access and the Frida CLI;
- local OAST requires an explicitly published callback port and externally routable address;
- custom plugins execute arbitrary Python in the scanner process;
- untrusted template DSL and pickle/RAG files must not be mounted.

Create a separate, explicitly reviewed Compose override for those features instead of weakening the default service.

## Verification commands

These were not run while the files were authored. With permission, verify in increasing order of impact:

```bash
# Parse Compose configuration only
docker compose config

# Build the core image
docker compose build deep-eye

# Confirm the inert default and CLI imports
docker compose run --rm deep-eye --version
docker compose run --rm deep-eye --help

# Build and inspect the optional browser image
DEEP_EYE_DOCKER_TARGET=browser docker compose build deep-eye
```

Do not perform a live scan as a verification step unless an authorized target and scope have been supplied explicitly.
