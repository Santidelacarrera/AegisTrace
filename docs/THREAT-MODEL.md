# Modelo de amenazas

Alcance: la API, la interfaz, el servicio de analítica y sus dependencias (PostgreSQL, Redis, proveedor LLM, IdP). Método: activos → fronteras de confianza → amenazas → mitigación y riesgo residual. Cada mitigación indica dónde se prueba.

## Activos
1. **Eventos y alertas** (pueden contener datos personales: usuarios, IPs).
2. **Integridad de las decisiones**: qué se recomendó, quién aprobó, qué se ejecutó (auditoría).
3. **Credenciales**: contraseñas (hash scrypt), semillas TOTP (cifradas), claves API de servicio, claves de firma.
4. **Aislamiento entre organizaciones.**

## Fronteras de confianza
- **Fuentes de logs → API:** datos *no confiables*, incluido su texto libre.
- **Navegador → API:** autenticado por token; el navegador es entorno hostil (XSS).
- **API → proveedor LLM:** salen datos estructurados del incidente; vuelve texto *no confiable*.
- **API → analítica / IdP / PostgreSQL / Redis:** red interna; el IdP es externo.

## Amenazas y mitigaciones

| # | Amenaza | Mitigación | Prueba | Riesgo residual |
|---|---|---|---|---|
| 1 | **Inyección en logs** (instrucciones dentro de un evento para manipular al analista o al LLM) | El proveedor determinista solo lee campos estructurados; al LLM nunca se envía `message`; los eventos van entre `<incident_data>` y no pueden cerrar el delimitador; la salida pasa por validador de citas y no puede crear acciones | `api.test › treats log content as data`, `llm.test › sends events as delimited data` | Un LLM puede razonar mal con datos estructurados manipulados (p. ej. IPs inventadas). Siempre hay aprobación humana. |
| 2 | **Alucinación del LLM** (citas falsas, recomendaciones sin base) | Cada ID citado debe pertenecer al incidente; sin evidencia no hay hipótesis ni recomendación; el servidor decide qué es ejecutable | `llm.test`, `api.test › discards analyses…` | Que una cita *exista* no prueba que *respalde* la afirmación. |
| 3 | **Ejecución de acciones sin permiso** | Las acciones nacen pendientes, solo simuladas, solo en ámbito de laboratorio; aprueba otra persona con `actions:approve`; el proponente no puede aprobar | `api.test › controlled response` | Si se implementaran acciones reales habría que revisar este modelo completo. |
| 4 | **Acceso entre organizaciones** | `orgId` sale de la credencial, nunca del cliente; todo acceso pasa por `Store.org(orgId)`; IDs ajenos dan 404 | `api.test › organization isolation`, `users.test › isolated per organization` | Un fallo de programación en un handler nuevo podría saltarse el patrón; no hay RLS en la base. |
| 5 | **Fuerza bruta / credential stuffing contra el login** | scrypt, bloqueo tras 5 fallos (compartido vía Redis), errores idénticos para usuario inexistente, MFA TOTP con códigos de un solo uso, rate limiting | `auth.test`, `limits.test` | El bloqueo permite denegar el acceso a un usuario legítimo (DoS dirigido). |
| 6 | **Robo de sesión** | Tokens firmados con caducidad (8 h; SSO 1 h); cambiar la contraseña o desactivar al usuario invalida los anteriores; CSP `script-src 'self'`, sin `eval` ni scripts en línea; texto de logs renderizado como texto | `users.test`, `app.test (escapes untrusted text)` | El token vive en `sessionStorage`: un XSS lo robaría. No hay revocación individual de tokens SSO. |
| 7 | **Manipulación de la auditoría** | Cadena HMAC por organización; ancla externa que detecta también el truncado final; fallos del ancla visibles en `/metrics` | `api.test › audit trail`, `auth.test › external audit anchor` | Quien tenga la clave HMAC **y** escriba en la base puede rehacer la cadena; el ancla solo ayuda si está fuera de su alcance. |
| 8 | **Compromiso de la base de datos** | Contraseñas con scrypt; semillas TOTP cifradas con AES-GCM (`AEGIS_DATA_KEY`); códigos de recuperación guardados como hash | `persistence.test › sealed`, `users.test` | Eventos y metadatos en claro. La clave de datos no se puede rotar todavía. |
| 9 | **Abuso de ingesta** (DoS, datos enormes) | Límites de cuerpo (512 KB JSON / 1 MB CSV), de lote (1000), rate limiting por credencial, campos truncados | `api.test › rejects oversized batches`, `limits.test` | La detección recorre todos los eventos de la organización en cada ingesta (coste lineal). |
| 10 | **SSO mal configurado o falsificado** | PKCE, `state` de un solo uso, `nonce`, firma/emisor/audiencia/caducidad verificados; sin rol por defecto | `oidc.test` | Probado con un IdP simulado, no con uno real. |
| 11 | **Secretos expuestos** | Obligatorios en producción; sin valores por defecto fuera de desarrollo; `.env` fuera del repositorio; hash sin `$` para no corromperse en `.env` | `config.test`, `auth.test` | Sin integración con un gestor de secretos; rotar `AEGIS_SESSION_KEY` cierra todas las sesiones, rotar `AEGIS_AUDIT_KEY` invalida la verificación histórica. |
| 12 | **Dependencias vulnerables** | `npm audit` y `pip-audit` en el CI; versiones fijadas en Python | CI | `dependency-review` de GitHub pendiente de activar en el repositorio. |
| 13 | **Exposición de datos al proveedor LLM** | Solo campos estructurados del incidente; no se envía texto libre; proveedor opcional y desactivado por defecto | `llm.test` | Usuarios, IPs y recursos sí salen hacia el proveedor: decidir según la política de datos de cada organización. |
| 14 | **Retención excesiva de datos personales** | Retención configurable que borra de memoria y de la base, conservando la evidencia de incidentes abiertos | `users.test › retention`, `persistence.test` | La auditoría no se purga automáticamente (hacerlo rompería la cadena). |

## Fuera de alcance / no cubierto
- Ataques al host, contenedor o red (hardening del sistema operativo, aislamiento de red).
- Cadena de suministro más allá de las auditorías de dependencias (sin firma de imágenes ni SBOM).
- Suplantación de la fuente de eventos con una clave de servicio robada: un colector comprometido puede inyectar eventos falsos (pueden crear alertas, no acciones).
