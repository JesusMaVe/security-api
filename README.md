# security-api — Backend con login LDAP, secrets rotados y cifrado en BD

Backend del ejercicio en Go. Autentica usuarios contra OpenLDAP (repo `security-ldap`), protege la API con `x-api-key` (inyectada server-side por el gateway BFF) y guarda datos cifrados con Fernet en SQLite.

Los secrets **ya no se rotan dentro de la app**: los rota el repo `secret-rotator` cada 2 minutos y los publica en `/shared/backend.env`, que este servicio relee en caliente.

```
Browser :8080 ──▶ OpenResty gateway (security-frontend) ──▶ Go API :8080 (host :8081)
                   /api/* + x-api-key (de /shared/frontend.env)     │
                                                                    ├─▶ OpenLDAP :389 (search-then-bind)
                                                                    ├─▶ SQLite /data/app.db (solo texto cifrado)
                                                                    └─◀ /shared/backend.env (API_SECRET, LDAP_BIND_PASSWORD)
```

## Requisitos

- **Docker 20+** (vía recomendada) o **Go 1.25+**
- `security-ldap` corriendo en `:389` y `../shared/backend.env` creado por `secret-rotator/rotate.sh`

## Configuración

| Variable | Default | Descripción |
|---|---|---|
| `SECRETS_FILE` | `/shared/backend.env` | Archivo `export K=V` escrito por `secret-rotator`. Se relee cuando cambia (mtime). Contiene `API_SECRET`, `API_SECRET_PREVIOUS`, `LDAP_BIND_PASSWORD`. |
| `DATABASE_ENCRYPTION_KEY` | clave Fernet de ejemplo | Cifra/descifra registros en SQLite. **Nunca rota.** |
| `LDAP_URL` | `ldap://host.docker.internal:389` | Servidor LDAP |
| `LDAP_BIND_DN` | `cn=readonly,dc=example,dc=com` | Cuenta de servicio para buscar usuarios |
| `LDAP_USERS_DN` | `ou=users,dc=example,dc=com` | Base de búsqueda de usuarios |
| `DB_PATH` | `/data/app.db` | SQLite |
| `ALLOW_ORIGIN` | `*` | CORS — en prod restringir |
| `PORT` | `8080` | Puerto interno |

Si `SECRETS_FILE` no existe o no define una variable, se usa la variable de entorno del mismo nombre.

## Ejecución — Docker

```bash
../secret-rotator/rotate.sh                     # crea ../shared/*.env (1a vez)
(cd ../security-ldap && docker compose up -d)   # LDAP
docker compose up --build -d                     # :8081
curl -i http://localhost:8081/health
```

## Endpoints

| Método | Ruta | `x-api-key` | Sesión | Respuesta |
|---|---|---|---|---|
| GET | `/health` | No | No | `{"status":"ok"}` |
| POST | `/api/login` | Sí | No | Body `{"username","password"}` → `200 {authenticated,username,displayName,mail}` + cookie `session` (HttpOnly, SameSite=Strict) / `401` |
| POST | `/api/logout` | Sí | — | Borra la sesión |
| GET | `/api/me` | Sí | Sí | Usuario de la sesión |
| GET | `/api/data` | Sí | Sí | Descifra y devuelve el último registro |
| POST | `/api/data` | Sí | Sí | Body `{"text"}`; cifra y guarda |

Errores: key inválida → `401 {"error":"unauthorized"}`; sin sesión → `401 {"error":"login required"}`; LDAP caído → `502`.

### Login (search-then-bind)

1. Bind como `LDAP_BIND_DN` con `LDAP_BIND_PASSWORD` vigente (si LDAP lo rechaza, relee el archivo y reintenta una vez — cubre el instante de rotación).
2. Busca `(&(objectClass=inetOrgPerson)(uid=<usuario escapado>))`.
3. Bind con el DN encontrado y el password del usuario. Password vacío se rechaza.
4. Crea una sesión aleatoria en memoria (30 min). No hay secret de firma, por lo que la rotación no invalida sesiones.

### Rotación del `API_SECRET` sin cortes

Se acepta `API_SECRET` **o** `API_SECRET_PREVIOUS` (comparación en tiempo constante). El rotador escribe `backend.env` antes que `frontend.env`, así que el gateway nunca queda con una key rechazada.

## Tests

```bash
go test ./...   # health, login/logout/me, auth por key y sesión, round-trip cifrado, rotación de key
```

## Ver los secrets

```bash
docker exec security-api sh -c '. /shared/backend.env && echo $API_SECRET'
docker exec security-api printenv DATABASE_ENCRYPTION_KEY   # no cambia
```

## Estructura

```
security-api/
├── main.go            # rutas, requireAPIKey (actual+previous), requireSession, login/logout/me, data
├── secret.go          # lector de SECRETS_FILE con recarga por mtime
├── ldap.go            # authenticator LDAP (go-ldap/v3): search-then-bind
├── session.go         # sesiones opacas en memoria
├── crypto.go          # Fernet con DATABASE_ENCRYPTION_KEY fijo
├── store.go           # SQLite
├── main_test.go
├── Dockerfile / docker-compose.yml
└── .env.example
```

## Seguridad

Valores de laboratorio. En producción: cookie `Secure` detrás de HTTPS, LDAPS, sesiones en un store compartido y secretos desde Vault/SSM.
