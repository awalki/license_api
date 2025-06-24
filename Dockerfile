# Dockerfile for License API
# author: awalki
# Available environment variables:
# - SECRET_KEY (required)
# - access_token_expire_minutes (default: 30)
# - ALGORITHM (default: HS256)
#
# To provide a secret to a docker image use the following command:
# docker run -e SECRET_KEY="YOUR_SECRET_KEY" -p 8080:8080 license_api
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

COPY . .

ENV PORT=8080

EXPOSE $PORT

CMD uv run fastapi run --port $PORT
