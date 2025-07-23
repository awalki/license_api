# License API

A robust license management API built with FastAPI, SQLModel, and aiogram for Telegram integration. This system allows you to easily integrate license validation into your software products to prevent unauthorized usage.

## ✨ Features

- **License Management**: Create, validate, and manage software licenses
- **FastAPI Backend**: High-performance async API with automatic documentation
- **SQLModel Integration**: Type-safe database operations with SQLAlchemy
- **Telegram Bot**: Manage licenses through a convenient Telegram interface
- **Redis Caching**: Fast license validation with Redis support
- **Authentication**: Secure API endpoints with token-based auth
- **Docker Support**: Easy deployment with Docker containers

## 📋 Requirements

- Python 3.13
- Redis server
- Telegram Bot Token

## 🚀 Quick Start

### Option 1: Docker (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd license-api
   ```

2. **Build and run with Docker**
   ```bash
   docker build -t license_api .
   
   docker run \
     -e SECRET_KEY="your-secret-key-here" \
     -e ADMIN_ID="your-telegram-admin-id" \
     -e WEBHOOK_URL="https://your-domain.com/webhook" \
     -e BOT_TOKEN="your-telegram-bot-token" \
     -p 8080:8080 \
     license_api
   ```

3. **Access the API**
   - API: `http://localhost:8080`
   - Documentation: `http://localhost:8080/docs`

### Option 2: Manual Installation

1. **Install UV package manager**
   ```bash
   # Visit https://docs.astral.sh/uv/getting-started/installation/
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Generate secret key**
   ```bash
   openssl rand -hex 32
   ```

3. **Setup environment variables**
   
   Create a `.env` file in the project root:
   ```env
   SECRET_KEY="your-generated-secret-key"
   ADMIN_ID="your-telegram-user-id"
   WEBHOOK_URL="https://your-domain.com/webhook"
   BOT_TOKEN="your-telegram-bot-token"
   REDIS_URL="redis://localhost:6379"
   ```

4. **Install dependencies and run**
   ```bash
   uv sync
   uv run fastapi dev --port 8080
   ```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `SECRET_KEY` | JWT secret key for authentication | ✅ | `a1b2c3d4e5f6...` |
| `ADMIN_ID` | Telegram admin user ID | ✅ | `123456789` |
| `WEBHOOK_URL` | Telegram webhook URL | ✅ | `https://api.example.com/webhook` |
| `BOT_TOKEN` | Telegram bot token from @BotFather | ✅ | `1234567890:ABC...` |
| `REDIS_URL` | Redis connection string | ❌ | `redis://localhost:6379` |

### Getting Telegram Credentials

1. **Create a bot**: Message [@BotFather](https://t.me/BotFather) on Telegram
2. **Get your Admin ID**: Message [@userinfobot](https://t.me/userinfobot) to get your user ID
3. **Set webhook**: To use telegram admin panel you have to open ports on your pc

## 📖 API Documentation

Once the server is running, visit:
- **Swagger UI**: `http://localhost:8080/docs`

### Example API Usage

```python
# pip install license-api-py

import asyncio
from license_api_py import LicenseAPI

api = LicenseAPI("http://localhost:8080")

user = {
    "username": "bluniparker",
    "password": "your-password",
    "hwid": "your-hwid"
}

async def main():
    if (await api.login(user)):
        print("Logged in successfully!")
        await api.connect_to_websocket()
    else:
        print("Failed to login.")

if __name__ == "__main__":
    asyncio.run(main())
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

If you encounter any issues:
1. Check the [documentation](http://localhost:8080/docs)
2. Review the logs: `docker logs <container-name>`
3. Open an issue on GitHub

## ✅ Roadmap

- [x] Core API functionality
- [x] Telegram bot integration
- [x] Authentication system
- [x] Docker support
- [x] API rate limiting
- [ ] More Database support
- [ ] Web dashboard
- [ ] License analytics
- [ ] Bulk operations
