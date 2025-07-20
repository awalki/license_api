FROM valkey/valkey:7.2-bookworm as valkey
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app
COPY . .

ENV PORT=8080
EXPOSE $PORT 6379

COPY --from=valkey /usr/local/bin/valkey-server /usr/local/bin/

ENTRYPOINT valkey-server --daemonize yes && uv run fastapi run --port $PORT
CMD uv run fastapi run --port $PORT
