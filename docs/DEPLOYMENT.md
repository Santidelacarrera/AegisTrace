# Despliegue y operación

Probado en local con Docker (PostgreSQL 16, Redis 7, Caddy 2): la pila de producción arranca con TLS, rechaza credenciales demo, el login del admin real funciona y los datos sobreviven a reinicios y a una restauración. **No se ha desplegado en un servidor real ni en la nube.**

## 1. Puesta en marcha

```bash
cp .env.example .env              # rellena TODOS los valores (openssl rand -base64 48 para los secretos)
cd api && npm ci && npm run user-tool -- '<contraseña del admin>'   # pega el resultado en AEGIS_USERS
docker compose -f docker-compose.prod.yml up -d --build
```

- Apunta el DNS de `AEGIS_DOMAIN` al servidor; Caddy obtiene y renueva el certificado TLS solo (puertos 80/443 abiertos).
- Solo se publican 80/443. `/metrics` está oculto en el proxy; scrapéalo desde la red interna (`api:3000/metrics`).
- `GET /health` (vivo) y `GET /ready` (dependencias) para el orquestador.
- Entra en `https://<dominio>/ui/` con el admin y crea el resto de usuarios en *Usuarios*; cada uno cambia su contraseña temporal y puede activar MFA en *Mi cuenta*.

## 2. Secretos

| Variable | Para qué | Si se pierde o rota |
|---|---|---|
| `AEGIS_SESSION_KEY` | Firma de sesiones | Rotarla cierra todas las sesiones (seguro y sencillo). |
| `AEGIS_AUDIT_KEY` | HMAC de la auditoría | Sin ella no se puede verificar la cadena existente. **No hay rotación soportada**: guárdala y respáldala. |
| `AEGIS_DATA_KEY` | Cifra las semillas TOTP | Sin ella no se pueden descifrar los MFA guardados (habría que resetear el MFA de cada usuario). **No hay rotación soportada.** |
| `AEGIS_API_KEYS` | Colectores de eventos | Rótalas editando la lista y reiniciando. |

Guárdalas en un gestor de secretos y no en el repositorio. Mantén `AEGIS_AUDIT_KEY` en un lugar distinto del respaldo de la base de datos.

## 3. Auditoría y ancla

`AEGIS_AUDIT_ANCHOR_FILE` recibe una línea por entrada. Para que proteja de verdad frente a un atacante con acceso a la API, ese archivo debe vivir en almacenamiento que **la aplicación no pueda reescribir** (otro host vía syslog/rsyslog remoto, un volumen de solo anexado, un bucket con bloqueo de objetos). Con el volumen por defecto solo detecta errores. Comprueba periódicamente `GET /api/v1/audit/verify` (rol auditor o admin) y alerta si `valid` es `false`.

## 4. Copias de seguridad y restauración

```bash
DATABASE_URL=postgres://aegis:***@db:5432/aegis ./scripts/backup.sh          # con pg_dump instalado
docker compose -f docker-compose.prod.yml exec -T db pg_dump -U aegis aegis | gzip > aegis.sql.gz   # alternativa en contenedor

psql ... -c 'create database aegis_new'
DATABASE_URL=postgres://.../aegis_new ./scripts/restore.sh aegis.sql.gz       # se niega si la base no está vacía
```

Guarda junto a la copia: el archivo de ancla y (aparte) los secretos. **Ensaya la restauración**: arranca la API contra la base restaurada y comprueba que `/audit/verify` devuelve `valid: true` (se hizo en local: 307 documentos y 17 entradas de auditoría, cadena íntegra).

## 5. Retención

`AEGIS_RETENTION_DAYS` (eventos) y `AEGIS_INCIDENT_RETENTION_DAYS` (incidentes cerrados, por defecto 3×) activan un borrado cada 6 h y bajo demanda: `POST /api/v1/admin/retention/run {"dryRun": true}` (por defecto simula). Nunca se borra evidencia de incidentes abiertos. La **auditoría no se purga**: eliminar un prefijo rompería la cadena, así que su retención es una decisión y operación aparte.

## 6. Monitorización sugerida (`/metrics`)

| Señal | Alerta sugerida |
|---|---|
| `aegistrace_request_duration_ms_*` | p95 sostenido > 1 s |
| `aegistrace_rateLimited_total` | Subida brusca |
| `aegistrace_denied_total` | Subida brusca (intentos de acceso) |
| `aegistrace_anchorErrors_total` | Cualquier incremento (el ancla no se está escribiendo) |
| `/ready` ≠ 200 | Base de datos inaccesible |
| `audit/verify` → `valid:false` | Crítica: posible manipulación |
| log `analytics_unavailable`, `redis_unavailable_using_local_limits`, `persist_failed` | Revisar la dependencia |

## 7. Límites conocidos (léelos antes de producción)

- **Una sola instancia de la API.** El estado de dominio vive en memoria de cada proceso; dos instancias sobre la misma base divergirían. Redis solo comparte los límites. Escalar horizontalmente requiere el modelo relacional con transacciones (ver ADR 0002).
- Coste lineal de la detección por ingesta: ~35 ms por lote de 500 eventos con 30 000 en memoria. Dimensiona la memoria según el volumen de eventos y la retención.
- Sin migraciones versionadas más allá de `api/migrations/001_init.sql` (idempotente).
- Las claves `AEGIS_AUDIT_KEY` y `AEGIS_DATA_KEY` no se pueden rotar.

## 8. Actualizar

```bash
git pull && docker compose -f docker-compose.prod.yml up -d --build   # la API recarga el estado desde PostgreSQL al arrancar
```

Haz una copia antes. El apagado es ordenado (SIGTERM): termina las peticiones en curso y sus escrituras.
