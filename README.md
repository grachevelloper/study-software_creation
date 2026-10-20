# Markdown Notes

Работающий учебный MVP на Go для создания Markdown-заметок и доступа к ним по временным ссылкам. HTTP-сервер, авторизация и бизнес-логика написаны на Go; данные хранятся в SQLite через pure-Go драйвер.

## Реализовано

- регистрация и вход с безопасным хэшированием пароля;
- HMAC-подписанные access-токены и отзываемые refresh-токены;
- создание заметки со сроком жизни 7, 30 или 90 дней;
- чтение и изменение владельцем;
- optimistic locking по полю `revision`;
- share-токены `READ` и `WRITE` с необязательным сроком действия;
- простой адаптивный веб-интерфейс;
- healthcheck и метрики Prometheus;
- SQLite-хранилище, интеграционные тесты, Docker Compose и Nginx.

## Локальный запуск

```bash
go mod download
make test
make run
```

После запуска интерфейс доступен на [http://127.0.0.1:8080](http://127.0.0.1:8080), а проверка развертывания выполняется командой:

```bash
make smoke
```

Данные сохраняются в `data/notes.db`. Значения для учебного запуска заданы в `Makefile`; для публичного окружения обязательно укажите длинный случайный `JWT_SECRET`.

## Запуск через Docker Compose

```bash
cp .env.example .env
# заменить JWT_SECRET в .env
docker compose config --quiet
docker compose up --build -d
docker compose ps
go run ./cmd/smoke http://127.0.0.1:8080
```

В Compose приложение находится во внутренней сети, запускается без root и Linux capabilities, а наружу публикуется только Nginx на порту 8080. Для сервера с доменом перед Nginx следует добавить TLS-терминацию или расширить конфигурацию сертификатами Let's Encrypt.

## Основные файлы

- `main.go` - HTTP API, авторизация и SQLite;
- `static/` - браузерный интерфейс;
- `main_test.go` - интеграционный пользовательский сценарий;
- `compose.yaml` и `Dockerfile` - контейнерное развертывание;
- `deploy/nginx.conf` - reverse proxy и rate limit;
- `cmd/smoke/` - проверка живого стенда на Go;
- `Api-Contract.json` - OpenAPI 3.0.3;
- `PLAN.md` - исходный план проекта.
