# KeyboxStore

A FastAPI service for uploading Android attestation keybox XML, reading leaf
certificate metadata, and exporting individual keyboxes. Only the latest uploaded
file is stored, using the [OhMyKeymint XML format](https://github.com/qwq233/OhMyKeymint/blob/master/template/keybox.xml).

## Run

With Python 3.14+ and [uv](https://docs.astral.sh/uv/):

```sh
uv sync --locked
uv run keyboxstore
```

Or with Docker Compose:

```sh
docker compose -f compose.example.yaml up --build -d
```

The API is available at `http://127.0.0.1:8000`.
Local runs store XML at `data/keybox.xml`; set `KEYBOX_FILE` to override it.
Compose stores XML in a persistent named volume.

## API

| Method | Path | Description |
| --- | --- | --- |
| POST | `/keyboxes` | Upload XML as multipart field `file` |
| GET | `/keyboxes` | List keyboxes and leaf certificate metadata |
| GET | `/keyboxes/{index}` | Get one keybox's metadata |
| GET | `/keyboxes/{index}/export` | Download one keybox with its private keys and full chains |

```sh
curl -F 'file=@keybox.xml' http://127.0.0.1:8000/keyboxes
curl http://127.0.0.1:8000/keyboxes
curl -o keybox-0.xml http://127.0.0.1:8000/keyboxes/0/export
```

Indexes start at zero and refer to the current file. Uploads are limited to
10 MiB; a valid upload atomically replaces the previous file. Invalid uploads
leave it intact.

Metadata describes the first certificate in each RSA or ECDSA chain: subject,
issuer, serial number, validity dates, SHA-256 fingerprint, signature algorithm,
and public key size. Keys must match their first certificate. Certificate trust,
revocation, and expiration are not checked.

Private keys are stored in plaintext and included in exports. There is no built-in
authentication; use an authenticated TLS proxy for external access.

## Notifications

Set `NTFY_URL` to an [ntfy topic URL](https://docs.ntfy.sh/publish/) to receive a
notification after each successful upload. Optionally set `NTFY_TOKEN` for bearer
authentication. Leave `NTFY_URL` unset to disable notifications.

```sh
NTFY_URL=https://ntfy.sh/your-topic uv run keyboxstore
```

Compose reads the same variables from your shell or a `.env` file. Notifications
include the keybox count and the first keybox's certificate validity dates for
each key algorithm, and run after the response is sent. Delivery is
best-effort, with a five-second network timeout and no retries; failures are logged
without affecting the saved file.

With ntfy enabled, the service also checks every keybox at startup and every
24 hours. It sends one notification listing leaf certificates with less than
two days remaining, including certificates already expired, with their keybox
indexes, algorithms, and UTC expiry times. Warnings repeat daily until the file
is replaced with valid certificates. Run one application worker to avoid duplicate
scheduled notifications.

## Development

```sh
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Tests use generated keys and the public OhMyKeymint fixture in `tests/fixtures/`.

## CI and releases

GitHub Actions runs tests, Ruff, and Compose validation on every push and pull
request. Pushing a Git tag (for example, `v0.1.0`) also builds and publishes
`ghcr.io/<owner>/<repository>:v0.1.0` and `:latest` after the checks pass.
Image names are lowercase; `latest` points to the most recently published tag.
Publishing uses the built-in `GITHUB_TOKEN`; no registry secret is needed.
