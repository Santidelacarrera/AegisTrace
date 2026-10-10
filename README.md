# AegisTrace

Plataforma de investigación y respuesta asistida para incidentes de seguridad. Convierte eventos dispersos en incidentes priorizados, investigables y auditables. El análisis asistido explica la evidencia y sugiere acciones; **las respuestas sensibles requieren permisos y aprobación humana**.

> **Estado:** MVP funcional con datos sintéticos: API, PostgreSQL, servicio de anomalías, interfaz React y análisis opcional con LLM. Ver [Alcance y limitaciones](#alcance-y-limitaciones) antes de usarlo en serio.

![Panel](docs/media/01-dashboard.png)
![Análisis de un incidente](docs/media/03-incident-analysis.png)

Vídeo del flujo completo (analista → aprobador → auditor): [`docs/media/demo.webm`](docs/media/demo.webm) · más capturas en [`docs/media/`](docs/media/).

## Qué hace hoy

| Capacidad | Implementación |
|---|---|
| Ingesta y normalización | `POST /api/v1/events` acepta objeto, array, `{events:[]}` o `text/csv`. Alias de campos, fecha → UTC ISO, IP validada, tipos canónicos, control chars eliminados, límites de tamaño. Idempotente por ID (o hash del contenido). |
| Detección por reglas | R001 fallos de login en ráfaga · R002 login exitoso tras fallos (crítica) · R003 password spraying · R010 errores de autorización · R020 cambio de permisos (admin / auto-concesión). Función pura y determinista. |
| Detección estadística | Servicio FastAPI (`analytics/`): picos de fallos por usuario (z-score robusto) y login desde IP nueva. Opcional (`ANALYTICS_URL`) y *fail-open*. Mide peor que las reglas, ver [Evaluación](#evaluación). |
| Correlación | Alertas → incidentes por usuario/IP compartidos en ventana de 30 min; cada incidente guarda `linkReasons` con el porqué. |
| Investigación asistida | `POST /incidents/{id}/analysis` con proveedor determinista o LLM (Anthropic u OpenAI, `AEGIS_ANALYSIS_PROVIDER=anthropic|openai`): resumen, hipótesis con confianza, alternativas benignas, recomendaciones y **lagunas de datos**. Cada cita se valida contra los eventos del incidente; si no, se descarta (502). |
| Gestión de incidentes | Estados con transiciones válidas, responsable, etiquetas, comentarios, línea de tiempo, filtros, búsqueda y paginación. |
| Respuesta controlada | Solo **simuladas** (`block_ip`, `disable_user`), limitadas a un ámbito de laboratorio (`192.0.2/24`, `198.51.100/24`, `203.0.113/24`, `10/8`, usuarios `lab.*`). Propuesta → aprobación por otra persona → ejecución simulada. |
| Autenticación | Contraseña (scrypt) + **MFA TOTP** opcional por usuario (RFC 6238, códigos de un solo uso) → token HMAC con caducidad; bloqueo tras 5 fallos; **SSO OIDC** (código + PKCE, `state`, `nonce`, `id_token` verificado con JWKS, grupos → roles); claves API para cuentas de servicio. Quitar un usuario local revoca sus sesiones. |
| Persistencia | PostgreSQL con escritura antes de responder y recarga al arrancar (`DATABASE_URL`); sin ella, memoria. Eventos en inserción por lotes. |
| Límites compartidos | Rate limiting y bloqueo de login en memoria o en **Redis** (`REDIS_URL`), compartidos entre instancias. |
| Auditoría | Cadena HMAC por organización: consultas, denegaciones, logins, aprobaciones y ejecuciones. `GET /audit/verify` detecta ediciones y borrados; con ancla externa (`AEGIS_AUDIT_ANCHOR_FILE`) también el truncado del final. |
| Interfaz | React + TypeScript en `/ui/`: login (con código MFA y botón SSO), panel (alertas por severidad, incidentes abiertos, mediana de triage, falsos positivos), búsqueda y filtros, detalle con línea de tiempo y análisis, aprobaciones, auditoría. |
| Operación | Logs JSON estructurados, `/health`, `/metrics` (contadores), rate limiting por clave. |

## Arquitectura

```mermaid
flowchart LR
  S[Fuentes JSON/CSV] -->|POST /events| I[Ingesta + normalización]
  I --> E[(Eventos)]
  E --> R[Reglas deterministas]
  E -.->|opcional, fail-open| AN[Analítica FastAPI]
  AN -.-> A
  R --> A[(Alertas)]
  A --> C[Correlación]
  C --> N[(Incidentes + timeline)]
  N --> P[Proveedor de análisis: reglas o LLM]
  P --> V{Validador de citas}
  V -->|válido| Rec[Recomendaciones]
  V -->|cita inventada| X[Descartado 502]
  Rec -->|propone analista| Act[Acción pendiente]
  Act -->|aprueba OTRA persona con permiso| Sim[Ejecución simulada en estado de laboratorio]
  I & N & Act & Sim -.-> Aud[(Auditoría HMAC + ancla externa)]
  DB[(PostgreSQL)] <-.->|escritura antes de responder| E & A & N & Aud
  RB[RBAC + ámbito de organización] -.-> I & N & Act
  UI[React /ui/] --> RB
```

Capas: `api/src` — `normalize` → `rules` (+ `analytics`) → `pipeline` (alertas + correlación) → `analysis`/`llm` → `app` (HTTP, auth, RBAC, auditoría) → `persistence`. `store` es el único acceso a datos y siempre exige `orgId`. `web/` es la interfaz, `analytics/` el servicio de anomalías, `api/migrations/` el esquema usado.

## Puesta en marcha

```bash
docker compose up --build            # API+UI en http://localhost:3000/ui/ , PostgreSQL, Redis, analítica
```

Sin Docker:

```bash
cd api && npm ci && npm run dev                              # API en :3000 (memoria; con DATABASE_URL usa PostgreSQL)
cd web && npm ci && npm run build                            # compila la UI a api/public (servida en /ui/)
cd analytics && pip install -r requirements.txt && uvicorn app.main:app --port 8000   # opcional; ANALYTICS_URL=http://localhost:8000
./scripts/demo.sh                                            # flujo completo por API (BASE=http://localhost:3000)
cd web && node e2e/capture.mjs                               # regenera capturas y vídeo (requiere Chromium y ffmpeg)
```

Pruebas y evaluación:

```bash
cd api && TEST_DATABASE_URL=postgres://… TEST_REDIS_URL=redis://… npm test   # 88 pruebas (sin esas variables se omiten las de PostgreSQL y Redis)
cd api && npm run eval                              # reglas sobre el dataset de desarrollo y el holdout
cd web && npm test                                  # 5 pruebas de componentes
cd web && npm run e2e                               # E2E en navegador real (API en :3000 con el dataset cargado; se ejecuta en el CI)
cd analytics && pytest && python evaluate.py        # 7 pruebas y evaluación de los detectores estadísticos
```

**Credenciales de demostración** (solo con `NODE_ENV != production`): usuarios `ana` (analyst), `alex` (approver), `aude` (auditor), `vera` (viewer), `root-admin` (admin) en `org-acme` y `olivia` en `org-globex`, con contraseña `demo-<rol>`; claves API `demo-ingestor`, `demo-analyst`, … en la cabecera `x-api-key`. En producción hay que definir `AEGIS_API_KEYS`, `AEGIS_USERS` (hash scrypt), `AEGIS_AUDIT_KEY` y `AEGIS_SESSION_KEY`; si falta alguna, el servidor no arranca.

MFA: `npm run user-tool -- <contraseña> --mfa <usuario>` genera el hash scrypt y el secreto TOTP para una entrada de `AEGIS_USERS`.

Variables: `DATABASE_URL`, `REDIS_URL`, `ANALYTICS_URL`, SSO (`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`, `OIDC_ORG_ID`, `OIDC_ROLE_MAP`, `OIDC_GROUPS_CLAIM`, `AEGIS_SSO_TOKEN_TTL`), `ANALYTICS_URL`, `AEGIS_ANALYSIS_PROVIDER=anthropic` + `ANTHROPIC_API_KEY` (+ `AEGIS_LLM_MODEL`), o `AEGIS_ANALYSIS_PROVIDER=openai` + `OPENAI_API_KEY` + `AEGIS_LLM_MODEL` (obligatorio; `OPENAI_BASE_URL` para endpoints compatibles), `AEGIS_AUDIT_ANCHOR_FILE`, `AEGIS_RATE_LIMIT`, `AEGIS_MAX_BATCH`, `AEGIS_TOKEN_TTL`.

### Roles

| Rol | Permisos |
|---|---|
| viewer | lectura |
| ingestor | solo ingesta |
| analyst | lectura + ingesta + gestionar incidentes + pedir análisis + **proponer** acciones |
| approver | analyst + **aprobar/rechazar** (no puede aprobar lo que él mismo propuso) |
| auditor | lectura + auditoría |
| admin | todo |

### API

`POST /api/v1/events` · `GET /events` · `GET /alerts` · `GET /incidents` · `GET /incidents/{id}` · `POST /incidents/{id}/{status|comments|labels|assignee|analysis|actions}` · `POST /auth/login` · `GET /actions` · `POST /actions/{id}/{approve|reject}` · `GET /lab-state` · `GET /audit` · `GET /audit/verify` · `GET /dashboard`.

## Seguridad: qué está cubierto y cómo se prueba

- **Permisos en servidor** en cada ruta; las denegaciones se auditan (`test/api.test.ts › RBAC`).
- **Aislamiento entre organizaciones**: el `orgId` sale de la credencial, nunca del cliente; ver IDs ajenos da 404 (`› organization isolation`).
- **IA separada de la ejecución**: el análisis solo escribe recomendaciones; no existe ruta que ejecute una acción sin `actions:approve` y sin ser otra persona (`› controlled response`).
- **Logs = datos no confiables**: el proveedor determinista solo lee campos estructurados, nunca el texto libre; hay prueba con un mensaje con instrucciones inyectadas (`› treats log content as data`). Un proveedor LLM futuro pasaría por el mismo validador de citas.
- **Sesiones**: scrypt, tokens HMAC con caducidad, bloqueo por intentos, revocación al quitar el usuario, MFA TOTP con vectores del RFC 6238 y anti-reutilización de códigos (`test/auth.test.ts`); SSO con PKCE/state/nonce y rechazo de firma, audiencia, caducidad y nonce incorrectos (`test/oidc.test.ts`).
- **Entradas**: validación con zod/normalizador, límites (512 KB JSON, 1 MB CSV, 1000 eventos por lote), rate limiting.
- **Secretos**: sin claves en código para producción; el servidor se niega a arrancar con credenciales demo. El modelo LLM recibe solo campos estructurados dentro de un delimitador `<incident_data>` y nunca el texto libre de los logs.
- **Datos**: solo sintéticos (`data/synthetic`, regenerables con `npm run dataset`).

## Evaluación

`npm run eval` mide las reglas (alertas ≥ medium, nivel escenario) sobre dos datasets sintéticos etiquetados:

| Dataset | Eventos | Precisión | Recall | Escenarios benignos con alerta |
|---|---|---|---|---|
| **dev** (escrito junto con las reglas) | 248 | 1.00 | 1.00 | 0 % |
| **holdout** (otro generador, otros formatos de fuente, casos difíciles; no se usó para ajustar nada) | 387 | **0.44** | **0.65** | **32 %** |

El 1.00 del dev es por construcción: sirve como prueba de regresión. **Los números del holdout son los representativos**, y aun así siguen siendo sintéticos y escritos por el mismo autor. Qué falla en el holdout, y por qué:

- **No detecta** fuerza bruta lenta (1 intento cada ~2 min), *credential stuffing* (1 intento por usuario desde muchas IPs) ni escalada a un rol personalizado (`power_user_full_access`): los umbrales y la lista de roles admin no los cubren.
- **Falsas alarmas** en cuentas de servicio que reintentan, usuarios que olvidan la contraseña y vuelven a entrar, errores 403 tras un despliegue y promociones a admin legítimas: las reglas no conocen el contexto (cuentas de servicio, cambios aprobados).

Detectores estadísticos (`python evaluate.py`): `rate_spike` acierta 11 de 15 marcas en dev (precisión 0.73) y 10 de 23 en holdout (0.43), es decir, **no supera a las reglas**; `new_source_ip` tiene precisión 0 en ambos (en los datos sintéticos cada login usa una IP distinta). Por eso `new_source_ip` es solo señal: se muestra como alerta de severidad baja y puede enriquecer un incidente existente, pero nunca abre uno. Una prueba fija las métricas del holdout para que este texto no pueda quedar desfasado.

## Alcance y limitaciones

Implementado: ingesta, reglas, analítica estadística, correlación, análisis con citas (determinista y LLM), incidentes, acciones simuladas con aprobación, auditoría con ancla, login con sesiones, persistencia en PostgreSQL, interfaz React, Docker, CI, capturas y vídeo.

**Sigue sin hacerse, o con salvedades:**
- **LLM contra la API real**: no probado, porque no hay clave en este entorno. Lo que sí se probó: el contrato HTTP de ambos proveedores (ruta, cabeceras, cuerpo, timeout) contra servidores locales reales, y todo lo demás con respuestas simuladas. El validador garantiza que las citas existan, no que respalden la afirmación.
- **SSO**: probado contra un proveedor OIDC simulado que corre en HTTP real (discovery, JWKS, PKCE), **no contra un IdP real** (Keycloak, Okta, Entra…). No hay SAML. Una sesión SSO lleva el rol dentro del token (caducidad corta, 1 h por defecto) y **no se puede revocar** antes de caducar salvo rotando `AEGIS_SESSION_KEY`.
- **Recuperación de contraseña y gestión de usuarios**: no implementadas. Los usuarios locales se definen por configuración; cambiar una contraseña o registrar MFA es editar `AEGIS_USERS` (ver `user-tool`). El MFA TOTP no tiene códigos de recuperación.
- **BullMQ**: no se usa. Redis se emplea solo para límites compartidos; no hay trabajo asíncrono que justifique una cola. Si Redis cae, los límites degradan a memoria local con un aviso en el log.
- **Varias instancias**: los límites ya se comparten, pero **el estado no**: cada instancia mantiene su copia en memoria y dos procesos escribiendo en la misma base divergirían. La persistencia es por documentos JSONB (no el esquema relacional de `db/schema.sql`), sin RLS. Medido en local: ~18 ms por lote de 500 eventos con 6 000 en memoria y ~35 ms con 30 000; la detección sigue recorriendo todos los eventos de la organización en cada ingesta, así que crece linealmente.
- **Docker**: las imágenes y `docker compose` (API+UI, PostgreSQL, Redis, analítica) se construyeron y ejecutaron aquí, incluido el E2E del navegador contra los contenedores, pero con el espejo `mirror.gcr.io` porque Docker Hub devolvía 429 (`--build-arg REGISTRY=mirror.gcr.io/library`). **El workflow de GitHub Actions no se ha visto ejecutar**: solo se dispara en `main` y en pull requests.
- **Auditoría**: el ancla externa solo protege si `AEGIS_AUDIT_ANCHOR_FILE` está en almacenamiento que la aplicación no pueda reescribir; quien tenga la clave HMAC y escriba en la base de datos puede rehacer la cadena. Si falla la escritura del ancla, la API sigue funcionando, lo registra y lo cuenta en `/metrics` (`aegistrace_anchorErrors_total`).
- **Interfaz**: cubre el flujo principal; sin paginación visual ni gestión avanzada de etiquetas/comentarios.
- Sin trazas distribuidas; las métricas son contadores simples.

## Documentación

[0001 Reglas deterministas primero](docs/adr/0001-deterministic-rules-first.md) · [0002 Persistencia](docs/adr/0002-in-memory-store-for-mvp.md) · [0003 IA solo recomienda](docs/adr/0003-ai-recommends-humans-approve.md) · [0004 Auditoría encadenada](docs/adr/0004-hash-chained-audit.md) · [0005 Servicio de analítica](docs/adr/0005-analytics-service.md) · [0006 Autenticación, MFA y SSO](docs/adr/0006-auth-and-sessions.md) · [0007 Redis para límites](docs/adr/0007-redis-for-shared-limits.md)
