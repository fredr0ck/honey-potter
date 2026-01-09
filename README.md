# Honey Potter [[RU](./README.ru.md)]

Honeypot management system for monitoring and detecting attacks

## Quick start

1. Clone repository
```bash
git clone github.com/fredr0ck/honey-potter
cd honey-potter
```

2. Rename .env.example to .env
```env
ADMIN_USERNAME=CHANGE_ME
ADMIN_PASSWORD=CHANGE_ME

DATABASE_URL=postgresql://honeypot:honeypot_password@localhost:5432/honeypot_db

REDIS_URL=redis://localhost:6379/0

SECRET_KEY=CHANGE_ME

# Optional
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

DOCKER_SOCKET=unix://var/run/docker.sock

```

3. Start Docker
```bash
docker-compose up -d
```

4. Web will be available on http://localhost:3000


## Supported honeypots

- **PostgreSQL**: logs connections, authentication attempts, and SQL-queries
- **SSH**: logs connections and authentication attempts
- **HTTP**: logs HTTP requests

## Event levels

- **LOW (1)**: connections, port scanning
- **MEDIUM (2)**: bruteforce, command execution
- **CRITICAL (3)**: using a honeypot -> compromising the system
