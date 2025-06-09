# license_api
License API written in FastAPI &amp; SQLModel

You can easily integrate the api into your product to prevent unwelcome usage of your software

## TODO:

- telegram bot for giving licenses to users and admin panel
- documentation
- connection library for connecting api and software (currently working on rust crate)
- ~~simple auth~~

## How to setup

Firstly Install uv - https://docs.astral.sh/uv/getting-started/installation/

Then you have to create SECRET_KEY

```bash
openssl rand -hex 32
```

Finally you have to create .env file in the project root and provide a secret

```bash
SECRET_KEY = "ENTER_YOUR_SECRET_KEY"
```

To run the api

```bash
uv run fastapi run/dev --port [YOUR_PORT]
```
