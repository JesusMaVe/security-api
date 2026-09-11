# security-api — Backend con secret rotation + cifrado en BD (con BFF)

Backend del ejercicio en Go (stdlib). El API valida `x-api-key`, pero ya no la expone al cliente — el gateway OpenResty/NGINX (BFF) la inyecta server-side leyéndola de un archivo compartido que este mismo servicio actualiza cada 2 minutos.

> **Arquitectura:** este repo expone el API en `:8081` vía Docker. El frontend (`security-frontend`) lo consume a través del gateway OpenResty (`:8080` → `proxy_pass host.docker.internal:8081`).

```
Browser :8080 ──▶ OpenResty gateway (frontend, :80) ──▶ Go API :8080 (interno, host :8081)
                   │  /api/* (x-api-key leído de /shared/api_secret.env), /health
                   └──▶ dist/index.html (static)

security-api ──▶ SQLite (/data/app.db): guarda solo texto cifrado (Fernet)
             ──▶ /shared/api_secret.env: publica el API_SECRET vigente cada 2 min
```

## Requisitos

- **Docker 20+** (vía recomendada) o **Go 1.22+** para `go run` directo

## Configuración

Variables leídas de entorno / `.env` (ver `.env.example`):

| Variable | Default | Descripción |
|---|---|---|
| `API_SECRET` | `dev-secret-123` | Valor inicial del secreto que protege la API. Se **rota automáticamente cada 2 minutos** (ver `secret.go`) — el valor vivo se publica en `SECRET_SHARE_PATH`, no queda fijo al env var. |
| `DATABASE_ENCRYPTION_KEY` | clave Fernet de ejemplo | Llave usada para cifrar/descifrar los registros en SQLite. **Nunca rota** — si cambia, los registros existentes dejan de poder descifrarse. |
| `SECRET_SHARE_PATH` | `/shared/api_secret.env` | Archivo (montado también en el gateway) donde se publica `export API_SECRET=<valor>` en cada rotación. |
| `DB_PATH` | `/data/app.db` | Ruta del archivo SQLite. |
| `ALLOW_ORIGIN` | `*` | CORS `Access-Control-Allow-Origin` — en prod restringir |
| `PORT` | `8080` | Puerto interno del contenedor |

```bash
cp .env.example .env
```

## Ejecución — Docker (recomendada)

Requiere que exista `../shared/` (carpeta hermana, compartida con `security-frontend`):

```bash
mkdir -p ../shared
docker compose up --build -d
curl -i http://localhost:8081/health   # 200 directo al API
docker compose logs -f
docker compose down
```

## Endpoints

| Método | Ruta | API Key | Respuesta |
|---|---|---|---|
| GET | `/health` | No | `{"status":"ok"}` |
| GET | `/api/data` | Sí (`x-api-key`) | Descifra y devuelve el último registro guardado: `{"message","ciphertext_in_db","course","status"}` |
| POST | `/api/data` | Sí (`x-api-key`) | Body `{"text":"..."}`; cifra y guarda en SQLite: `{"stored":true,"id","ciphertext"}` |

Error sin/inválida key: `401 {"error":"unauthorized"}` (comparación `crypto/subtle.ConstantTimeCompare`).

## Tests

```bash
go test ./...   # health, auth, y round-trip encrypt→store→decrypt
```

## Rotación del API_SECRET (cada 2 minutos)

```bash
# Valor vivo (leído del archivo compartido, ya que un env var de proceso no puede cambiar en caliente):
docker exec <api-container> sh -c '. /shared/api_secret.env && echo $API_SECRET'
# Esperar ~2 min y repetir: el valor debe cambiar.

# La llave de cifrado NUNCA cambia:
docker exec <api-container> printenv DATABASE_ENCRYPTION_KEY
```

## Estructura

```
security-api/
├── main.go              # mux + middleware requireAPIKey + corsAll + handlers encrypt/store/decrypt
├── secret.go            # rotación de API_SECRET cada 2 min, publicada en SECRET_SHARE_PATH
├── crypto.go            # Encrypt/Decrypt Fernet con DATABASE_ENCRYPTION_KEY fijo (sin rotación)
├── store.go             # SQLite: insertRecord / latestRecord
├── main_test.go         # httptest: health, auth, round-trip
├── Dockerfile           # multi-stage
├── docker-compose.yml   # api:8081:8080, monta ../shared y volumen de datos
├── .env.example / .env  # dev defaults
└── go.mod
```

## Seguridad

Todos los valores en `.env.example` son **solo para laboratorio**. El `API_SECRET` rota automáticamente sin afectar al frontend (que nunca lo conoce, es inyectado server-side). El `DATABASE_ENCRYPTION_KEY` se mantiene fijo a propósito para no perder acceso a datos ya cifrados.
