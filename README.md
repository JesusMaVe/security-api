# security-api

Backend del ejercicio *API Key Auth Anti-Pattern* (Go, sin dependencias externas).

## Requisitos
- Go 1.22+

## Ejecución

```bash
go run .
# o con clave y puerto custom:
API_KEY=mi-secreto PORT=9000 go run .
```

Servidor en `http://localhost:8080`. Clave por defecto: `dev-secret-123`.

## Endpoints

| Método | Ruta         | API Key | Respuesta |
| ------ | ------------ | ------- | --------- |
| GET    | `/health`    | No      | `{"status":"ok"}` |
| GET    | `/api/data`  | Sí      | JSON estático |
| POST   | `/api/data`  | Sí      | `{"message":"POST received"}` |

## Tests con curl

```bash
# Test 1 — health sin key
curl -i http://localhost:8080/health                 # 200

# Test 2 — GET sin key
curl -i http://localhost:8080/api/data               # 401

# Test 3 — GET con key incorrecta
curl -i -H "x-api-key: wrong-key" http://localhost:8080/api/data  # 401

# Test 4 — GET con key correcta
curl -i -H "x-api-key: dev-secret-123" http://localhost:8080/api/data  # 200

# Test 5 — POST sin key
curl -i -X POST http://localhost:8080/api/data       # 401

# Test 6 — POST con key correcta
curl -i -X POST -H "x-api-key: dev-secret-123" http://localhost:8080/api/data  # 200
```

Tests automáticos: `go test ./...`

## Advertencia de seguridad

Este proyecto reproduce a propósito un anti-pattern: la clave se envía
directamente desde el cliente, por lo que **no es secreta** — cualquiera puede
leerla con DevTools. Un atacante que extraiga `x-api-key` del frontend tiene
acceso total a la API. No usar en producción.