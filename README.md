# License API
License API written in FastAPI &amp; SQLModel &amp; aiogram

You can easily integrate the api into your product to prevent unwelcome usage of your software

## TODO:

- ~~documentation~~
- ~~connection library for connecting api and software~~
- ~~simple auth~~
- ~~telegram bot~~

## How to setup

## Manually (Needed to setup redis manually)

Firstly Install uv - https://docs.astral.sh/uv/getting-started/installation/


```bash
openssl rand -hex 32
```

Finally you have to create .env file in the project root and provide needed data

```bash
SECRET_KEY = "ENTER_YOUR_SECRET_KEY"
ADMIN_ID = "ENTER_YOUR_ADMIN_ID"
WEBHOOK_URL = "https://your-webhook-for-telegram/webhook"
BOT_TOKEN = "ENTER_BOT_TOKEN"
```

To run the api

```bash
uv run fastapi run/dev --port [YOUR_PORT]
```

## Docker (Recommended)

```bash
docker build -t license_api .

docker run \
  -e SECRET_KEY="YOUR_SECRET_KEY" \
  -e ADMIN_PASSWORD="YOUR_ADMIN_PANEL_PASSWORD" \
  -e WEBHOOK_URL = "https://your-webhook-for-telegram/webhook" \
  -e BOT_TOKEN = "YOUR_BOT_TOKEN" \
  -p 8080:8080 \
  license_api
```
