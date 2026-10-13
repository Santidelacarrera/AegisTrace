# AegisTrace · Nota de sesión autónoma (2026-10-12)

*Nexus Security & AI Lab · rama `feat/aegistrace-autonomo-2026-10-12` · base `main`*

> La nota original de la bóveda (`1_Projects`) **no es accesible** desde el entorno de esta sesión. Esta copia vive en el repositorio. Hay que trasladarla a la bóveda manualmente.

## Objetivo

Tarea solicitada: línea de tiempo forense con eventos sintéticos; cadena de hashes verificable que detecte alteraciones; documentar el formato de evidencia.

## Estado

**100 % de la definición de terminado en la primera vuelta** (de 5 permitidas). No hubo que volver al paso 1.

## Tareas y evidencia

| Tarea | Entregable | Evidencia |
|---|---|---|
| Línea de tiempo forense con eventos sintéticos | `api/src/forensic.ts` (`collectInputs`, `buildEvidenceBundle`); endpoint `GET /api/v1/incidents/{id}/evidence`; escenario `data/synthetic/forensic/scenario.json` (8 eventos: fuerza bruta desde una IP, acceso correcto 2 min después, auto-concesión de admin) | `forensic bundle from the synthetic scenario` (5 pruebas, incluida la del orden temporal y los eventos ausentes) |
| Cadena de hashes verificable que detecte alteraciones | `api/src/evidence.ts` (JSON canónico, SHA-256, `verifyChain`, `verifyAnchor`); `api/src/forensic.ts` (`verifyEvidenceBundle`); verificador sin servidor `npm run verify-evidence` | `alteration detection` (7 casos con posición y motivo exactos), `limits` (3 casos), verificación del ejemplo versionado |
| Documentar el formato | `docs/EVIDENCE-FORMAT.md` (formato, canonicalización, algoritmo, tabla de qué detecta y qué no, versionado, datos personales); `docs/examples/` (paquete real y su copia alterada); ADR 0009 | Los ejemplos se regeneran con `npm run export-evidence-examples` y los verifica una prueba |

## Comandos ejecutados y resultado

| Comando | Resultado |
|---|---|
| `cd api && TEST_DATABASE_URL=… TEST_REDIS_URL=… npx vitest run` | **Test Files 12 passed (12); Tests 141 passed (141)** |
| `cd api && npm run typecheck` | sin errores |
| `cd api && npm run eval` | exit 0 (dev 1.00/1.00; holdouts sin cambios) |
| `cd api && npm audit --audit-level=high` (completo, incluido desarrollo) | found 0 vulnerabilities |
| `cd web && npx vitest run` | Tests 10 passed (10); `npm run typecheck` ok; `npm audit --audit-level=high` 0 vulnerabilities |
| `cd analytics && pytest -q` | 7 passed |
| `pip-audit -r analytics/requirements.txt` | No known vulnerabilities found |
| `node web/e2e/flow.mjs` (contra la pila local en reinicio limpio) | E2E passed (5 comprobaciones: login incorrecto, análisis con citas, aprobación, auditoría, alta de usuario con contraseña temporal) |
| Mutación: quitar la comprobación de `hash` en `verifyChain` | 5 pruebas fallan (la suite detecta el fallo) |
| Mutación: quitar la comprobación de `prev` | 2 pruebas fallan |
| `npm run verify-evidence -- ../docs/examples/evidence-bundle.json` | `valid: true`, 16 entradas |
| `npm run verify-evidence -- ../docs/examples/evidence-bundle.tampered.json` | `valid: false`, `brokenAt: 4`, `reason: hash_mismatch` |
| Semgrep (`javascript/express`, `browser/security`, `lang/security`, `typescript/lang/security`, `jsonwebtoken`) sobre `api/src` y `web/src` | 36 archivos, 2 avisos WARNING, 0 errores (ver falsos positivos) |
| Búsqueda de patrones peligrosos (`eval`, `child_process`, `innerHTML`, `Math.random`, MD5/SHA-1) en el código nuevo | sin coincidencias |

### Falsos positivos (Semgrep)

- `api/src/llm.ts` líneas 47 y 76 (`html-in-template-string`): son prompts para la API del LLM, con la etiqueta `<incident_data>` dentro de una cadena JSON. No se renderizan como HTML en ningún navegador. No se cambia el código.

### Herramientas no ejecutadas

- **Semgrep con el registro público** (`--config auto`, `p/*`): bloqueado por el proxy (403). Se usaron las reglas del repositorio `semgrep/semgrep-rules` clonado desde GitHub.
- **Bandit**: no se ejecutó, porque no hay código Python nuevo; el código Python de la analítica no cambió.
- **ESLint**: el proyecto no tiene configuración de ESLint; el lint de referencia es el typecheck estricto.

## Decisiones (bitácora)

| Fecha | Decisión | Motivo |
|---|---|---|
| 2026-10-12 | Cadena **SHA-256 sin clave** para la evidencia, separada de la auditoría HMAC | Terceros deben poder verificar sin secretos. La auditoría interna sigue con HMAC. |
| 2026-10-12 | La integridad frente a un atacante exige **ancla externa** (`head`, `entries`) y se documenta como límite | Quien puede escribir el paquete puede recalcularlo entero. Ocultarlo sería engañoso. |
| 2026-10-12 | Export restringido a **`audit:read`** (auditor y admin), y cada export queda en la auditoría | El paquete contiene datos personales y texto libre de logs. |
| 2026-10-12 | `generatedAt` y `generatedBy` fuera de la cadena | Dos exportaciones del mismo estado deben producir la misma cadena. |
| 2026-10-12 | Faltantes (`missing`) se declaran, no se ocultan | La retención puede borrar eventos citados por incidentes cerrados; el investigador debe saberlo. |
| 2026-10-12 | Orden total sin dependencia del idioma (comparación de cadenas, no `localeCompare`) | Que la misma entrada produzca siempre el mismo orden y los mismos hashes. |
| 2026-10-12 | Verificador como script independiente (`verify-evidence`) que **no** usa la base de datos ni el servidor | Un tercero debe poder verificar un paquete en su propio equipo. |
| 2026-10-12 | Escenario sintético de **8 eventos** con resultado conocido, no un dataset grande | Las pruebas necesitan un resultado exacto y comprobable. |
| 2026-10-12 | Se omite el nombre del modelo en el trailer `Co-Authored-By` de los commits | La instrucción del sistema prohíbe identificadores de modelo en artefactos del repositorio. Se mantiene `Claude-Session`. |
| 2026-10-12 | Se usa el espejo `mirror.gcr.io` para imágenes base, no se ejecuta Docker en esta vuelta | Docker Hub limita por cuota; no hubo cambios de imagen. |

## Pendientes para Santiago

1. **Trasladar esta nota a la bóveda** (`1_Projects`), porque aquí no es accesible.
2. **Confirmar el titular del copyright** en `NOTICE`. Hoy figura «Santidelacarrera and AegisTrace contributors»; la política de Nexus indica que el proyecto pertenece a la empresa.
3. **Decidir el ancla de producción**: dónde publicar `head`/`entries` (sistema de log remoto, almacenamiento con bloqueo, o canal externo). Sin ancla no hay protección frente a recálculo.
4. **Revisar y aprobar el PR**. No se ha hecho merge. La aprobación es humana.
5. **PR de la licencia Apache-2.0** (commit `21b1e8e`, ya incluido en esta rama porque la base es `main` y la licencia no estaba mergeada). Revisar que se acepte junto con esta funcionalidad o separarlo.
6. Pendientes ya conocidos (ver README): probar el LLM con clave real; desplegar en un servidor; activar el Dependency graph con `DEPENDENCY_REVIEW=true`.

## Riesgos conocidos

- **Sin ancla**, la cadena solo demuestra coherencia interna (truncado y recálculo completo no se detectan).
- **Datos personales** en los paquetes, incluido el texto libre de los logs. La retención no se aplica a los paquetes ya descargados.
- **`gh` no está autenticado** en el entorno; el PR se abre con las herramientas de GitHub del conector.
- **Semgrep** se ejecutó con reglas clonadas, no con el registro público. Cobertura menor que la de `p/*`.

## Riesgos aceptados

- La detección sigue siendo O(n) por ingesta; la línea de tiempo de un incidente es O(k log k) por el ordenamiento, con k registros del incidente.
