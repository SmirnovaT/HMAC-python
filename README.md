# HMAC: подпись и проверка сообщений

REST API сервис для подписи и проверки целостности сообщений по алгоритму HMAC-SHA256.

## Требования к окружению и установка

Для работы потребуется менеджер зависимостей `uv`. Установить его по инструкции из GitHub репозитория astral-sh/uv:
https://github.com/astral-sh/uv?tab=readme-ov-file#installation

Установка зависимостей:
```bash
# Linux/macOS
make sync

# Windows
uv sync
```

## Конфигурация

Создайте файл `config.json` в корне проекта:

```json
{
  "hmac_alg": "SHA256",
  "secret": "<base64-encoded-secret>",
  "log_level": "info",
  "listen": "0.0.0.0:8080",
  "max_msg_size_bytes": 1048576
}
```

### Генерация секрета

**Linux/macOS:**
```bash
openssl rand -base64 32
```

**Windows (PowerShell):**
```powershell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
```

**Важно:** На Linux/macOS установите права доступа:
```bash
chmod 600 config.json
```

### Ротация секрета

Для ротации секрета используйте утилиту:

```bash
uv run python src/rotate_secret.py
```

## Запуск сервера

```bash
# Linux/macOS
make run/api

# Windows
uv run python main.py
```

## Примеры curl

**Подписать сообщение:**
```bash
curl -X POST http://localhost:8080/sign \
  -H 'Content-Type: application/json' \
  -d '{"msg":"hello"}'
```

**Проверить подпись:**
```bash
curl -X POST http://localhost:8080/verify \
  -H 'Content-Type: application/json' \
  -d '{"msg":"hello","signature":"<signature-from-sign>"}'
```

## Ограничения учебной реализации

**Ограничения данного учебного примера:**

- Это **не шифрование** — содержимое сообщения не скрывается
- Это **не асимметричная электронная подпись** — нет сертификатов, меток времени, цепочек доверия и неотказуемости
- Это **симметричный MAC (HMAC)** — обе стороны используют один общий секретный ключ
- **Нет многоключевой валидации** — используется только один секрет
- **Ротация секрета простая** — утилита только генерирует и заменяет секрет, без миграции старых подписей
- Безопасность основывается на хранении общего секрета, его корректной ротации и ограничении доступа
- Решение обеспечивает проверку «сообщение не изменили и оно от того, кто знает ключ», но требует безопасного обмена ключом заранее
