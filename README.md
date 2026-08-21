# security-api — Backend API Key (con BFF)

Backend del ejercicio **API Key** en Go (stdlib). El API sigue validando `x-api-key`, pero ya no la expone al cliente — Nginx (BFF) la inyecta server-side.

> **Arquitectura con Nginx:** este repo expone el API en `:8081` vía Docker. El frontend (`security-frontend`) lo consume a través de Nginx (`:8080` → `proxy_pass host.docker.internal:8081`). Ver [docs/nginx-best-practices.md](../docs/nginx-best-practices.md).

```
Browser :8080 ──▶ Nginx (frontend, :80) ──▶ Go API :8080 (interno, host :8081)
                   │  /api/* , /health proxy_pass
                   └──▶ dist/index.html (static)
```

## Requisitos

- **Docker 20+** (vía recomendada) o **Go 1.22+** para `go run` directo
- `curl` para tests manuales

## Configuración

Variables leídas de entorno / `.env` (ver `.env.example`):

| Variable | Default | Descripción |
|---|---|---|
| `API_KEY` | `dev-secret-123` | Clave esperada en `x-api-key` |
| `ALLOW_ORIGIN` | `*` | CORS `Access-Control-Allow-Origin` — en prod restringir |
| `PORT` | `8080` | Puerto interno del contenedor |

```bash
cp .env.example .env   # ya incluido con dev-secret-123, listo para docker compose
# En prod: edita .env con secretos reales (Vault/SSM) — .env no se commitea con reales
```

## Ejecución — Docker (recomendada)

```bash
docker compose up --build -d
curl -i http://localhost:8081/health   # 200 directo al API
docker compose logs -f
docker compose down
```

El `Dockerfile` es multi-stage (`golang:alpine` → `alpine:3.20`, binario estático `CGO_ENABLED=0`, usuario no-root `65532`, `HEALTHCHECK` con `wget /health`). Ver `Dockerfile` y `.dockerignore`.

## Ejecución — Go directo (sin Docker)

```bash
go run .
# con env custom:
API_KEY=mi-secreto PORT=9000 ALLOW_ORIGIN=http://localhost:8080 go run .
```

Escucha en `http://localhost:8080` (Docker mapea a `8081` para no chocar con Nginx en `8080`).

## Endpoints

| Método | Ruta | API Key | Respuesta |
|---|---|---|---|
| GET | `/health` | No | `{"status":"ok"}` |
| GET | `/api/data` | Sí (`x-api-key`) | `{"message":"Protected data","course":"Security Exercise","status":"success"}` |
| POST | `/api/data` | Sí (`x-api-key`) | `{"message":"POST received"}` |

Error sin/inválida key: `401 {"error":"unauthorized"}` (comparación `crypto/subtle.ConstantTimeCompare`).

## Tests (7 del enunciado)

```bash
# Automáticos (validan el API tal cual)
go test ./...   # cubre 6 escenarios HTTP

# Manuales — directo al API (requiere key)
curl -i http://localhost:8081/health                                          # 1: 200
curl -i http://localhost:8081/api/data                                        # 2: 401 sin key
curl -i -H "x-api-key: wrong-key" http://localhost:8081/api/data             # 3: 401
curl -i -H "x-api-key: dev-secret-123" http://localhost:8081/api/data        # 4: 200
curl -i -X POST http://localhost:8081/api/data                                # 5: 401
curl -i -X POST -H "x-api-key: dev-secret-123" http://localhost:8081/api/data # 6: 200
# Vía Nginx BFF (inyecta key, sin header)
curl -i http://localhost:8080/health                                          # 200
curl -i http://localhost:8080/api/data                                        # 200 (BFF añade x-api-key)
# 7: frontend — ver security-frontend/README.md
```

## Nginx BFF (corrige el anti-pattern)

Nginx no solo es reverse proxy — es **BFF**: inyecta `proxy_set_header x-api-key "dev-secret-123"` server-side. El API sigue exigiendo la key, pero el browser ya no la ve. Config en `security-frontend/nginx.conf:25`. En prod usar `${API_KEY}` vía `envsubst` y `expose` en lugar de `ports`.

## Buenas prácticas Docker aplicadas

- Multi-stage, imagen mínima (~15 MB), no-root, `.dockerignore`, `HEALTHCHECK`, secretos vía `environment`/`--env-file` no en imagen.

## Estructura

```
security-api/
├── main.go              # mux + middleware requireAPIKey + corsAll
├── main_test.go         # httptest para los 6 escenarios
├── Dockerfile           # multi-stage
├── docker-compose.yml   # api:8081:8080
├── .env.example / .env  # dev defaults
└── go.mod
```

## Seguridad

Antes anti-pattern (key en cliente, visible en DevTools) — ahora corregido con BFF: key solo server-side. En prod: JWT/OAuth2 + `auth_request` en Nginx.
