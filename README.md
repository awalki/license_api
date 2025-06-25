# license_api
License API written in FastAPI &amp; SQLModel

You can easily integrate the api into your product to prevent unwelcome usage of your software

## TODO:

- telegram bot for giving licenses to users and admin panel
- documentation
- connection library for connecting api and software (~~currently working on rust crate~~)
- ~~simple auth~~

## How to setup

Firstly Install uv - https://docs.astral.sh/uv/getting-started/installation/

Then you have to create SECRET_KEY & ADMIN_PASSWORD

```bash
openssl rand -hex 32
```

Finally you have to create .env file in the project root and provide a secret + admin password

```bash
SECRET_KEY = "ENTER_YOUR_SECRET_KEY"
ADMIN_PASSWORD = "ENTER_YOUR_ADMIN_PASSWORD"
```

To run the api

```bash
uv run fastapi run/dev --port [YOUR_PORT]
```

### Admin panel

You can access the admin panel through the following URL:

```
http://localhost:8080/admin

username: admin
password: YOUR_ADMIN_PASSWORD
```

### Docker

Also you can run the license api with Docker

```bash
docker build -t license_api .

docker run \
  -e SECRET_KEY="YOUR_SECRET_KEY" \
  -e ADMIN_PASSWORD="YOUR_ADMIN_PANEL_PASSWORD" \
  -p 8080:8080 \
  license_api
```
