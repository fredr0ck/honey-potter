# Honey Potter

Система управления honeypot для мониторинга и обнаружения атак.

## Запуск

1. Клонируйте репозиторий:
```bash
git clone github.com/fredr0ck/honey-potter
cd honey-potter
```

2. Переименуйте .env.example в .env
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

3. Запустите Docker:
```bash
docker-compose up -d
```

4. Веб-интерфейс будет доступен на http://localhost:3000


## Поддерживаемые типы Honeypot

- **PostgreSQL**: логирует подключения, попытки аутентификации и SQL запросы
- **SSH**: логирует подключения и попытки аутентификации
- **HTTP**: логирует HTTP запросы

## Уровни событий

- **LOW (1)**: обычные подключения, сканирование портов
- **MEDIUM (2)**: попытки брутфорса, выполнение команд
- **CRITICAL (3)**: использование honeytoken, компрометация системы