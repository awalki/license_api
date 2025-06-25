# License API
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

![Image 1](https://cdn.discordapp.com/attachments/1367958850124382251/1387410766872969226/image.png?ex=685d3e77&is=685becf7&hm=5da8030d2fcb1db882025587087b6aab81694f7636a2ce094d878752cec13b12)

![Image 2](https://cdn.discordapp.com/attachments/1367958850124382251/1387411002361905182/image.png?ex=685d3eaf&is=685bed2f&hm=a9ec152c5ea25f33fe664aff87c004a4d75f5724eafb92539a73f3cc4dde1fbd)

![Image 3](https://cdn.discordapp.com/attachments/1367958850124382251/1387411363369844787/image.png?ex=685d3f05&is=685bed85&hm=c2a9c133d953d10502f69fde0b6c6c0a0d6ce8e371d851bd181d207fb88f6e19)
