# API Reference

turnpass-x exposes a FlareSolverr-compatible HTTP API.

## Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/` | POST | Main API endpoint. |
| `/v1` | POST | Main API endpoint (alias). |
| `/health` | GET | Health check. |

## Commands

### request.get

```json
{
  "cmd": "request.get",
  "url": "https://example.com/",
  "session": "my-session",
  "maxTimeout": 60000,
  "headers": {"X-Custom": "value"},
  "cookies": [{"name": "foo", "value": "bar"}],
  "returnOnlyCookies": false
}
```

### request.post

```json
{
  "cmd": "request.post",
  "url": "https://example.com/login",
  "postData": "user=alice&pass=secret",
  "session": "my-session",
  "maxTimeout": 60000
}
```

### sessions.create

```json
{
  "cmd": "sessions.create",
  "session": "my-session",
  "session_ttl_minutes": 30
}
```

### sessions.list

```json
{"cmd": "sessions.list"}
```

Returns a JSON array of session IDs in `solution.html`.

### sessions.destroy

```json
{
  "cmd": "sessions.destroy",
  "session": "my-session"
}
```

## Response format

```json
{
  "status": "ok",
  "message": "Challenge solved!",
  "startTimestamp": 1700000000000,
  "endTimestamp": 1700000005000,
  "version": "0.1.0-dev",
  "session": "my-session",
  "solution": {
    "url": "https://example.com/",
    "status": 200,
    "cookies": [{"name": "cf_clearance", "value": "..."}],
    "userAgent": "Mozilla/5.0 ...",
    "html": "<!DOCTYPE html>..."
  }
}
```

Error responses use `"status": "error"` with a `"message"` field.

## curl examples

### Health check

```bash
curl http://localhost:8191/health
```

### Create a session

```bash
curl -X POST http://localhost:8191/v1 \
  -H 'Content-Type: application/json' \
  -d '{"cmd": "sessions.create", "session": "test"}'
```

### List sessions

```bash
curl -X POST http://localhost:8191/v1 \
  -H 'Content-Type: application/json' \
  -d '{"cmd": "sessions.list"}'
```

### GET a page

```bash
curl -X POST http://localhost:8191/v1 \
  -H 'Content-Type: application/json' \
  -d '{"cmd": "request.get", "url": "https://example.com/", "maxTimeout": 60000}'
```

### Destroy a session

```bash
curl -X POST http://localhost:8191/v1 \
  -H 'Content-Type: application/json' \
  -d '{"cmd": "sessions.destroy", "session": "test"}'
```
