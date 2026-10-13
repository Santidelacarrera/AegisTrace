# Formato de evidencia forense: `aegistrace.evidence.v1`

*Nexus Security & AI Lab · AegisTrace*

Este documento describe el formato del paquete de evidencia que exporta `GET /api/v1/incidents/{id}/evidence` y cómo verificarlo **sin acceso al sistema ni a ningún secreto**. Hay un ejemplo real generado con datos sintéticos en [`docs/examples/evidence-bundle.json`](examples/evidence-bundle.json), y su copia alterada en [`docs/examples/evidence-bundle.tampered.json`](examples/evidence-bundle.tampered.json).

## 1. Qué contiene

Un paquete recoge los hechos de un incidente, ordenados en el tiempo y encadenados por hash:

| `kind` | Origen | `at` | `data` (contenido verificado) |
|---|---|---|---|
| `event` | evento normalizado | `timestamp` del evento | tipo, severidad, usuario, IP, recurso, atributos (incluido el texto libre del log, tratado como dato) |
| `alert` | alerta de reglas | `firstSeen` | id de regla, severidad, sujeto, `lastSeen`, eventos citados |
| `analysis` | análisis asistido | `generatedAt` | proveedor, resumen, citas, lagunas declaradas |
| `activity` | línea de tiempo del incidente | instante de la acción | tipo de actividad (estado, comentario, etiqueta, asignación, acción…) |

Cada registro tiene estos campos:

| Campo | Tipo | Significado |
|---|---|---|
| `seq` | entero ≥ 1 | posición en la cadena (1, 2, 3…) |
| `at` | ISO-8601 UTC | instante del hecho |
| `kind` | texto | `event`, `alert`, `analysis` o `activity` |
| `source` | texto | origen (`aegistrace.rules`, `aegistrace.analysis`, `aegistrace.incident` o el `source` del evento) |
| `actor` | texto | quién produjo o registró el hecho (`system` si lo produjo el motor de reglas) |
| `summary` | texto | resumen legible; **no es la fuente de verdad**, la fuente es `data` |
| `refs` | lista de ids | eventos, alertas o análisis a los que se refiere (`refs[0]` es el principal) |
| `data` | objeto | contenido completo; se hashea con todo lo demás |
| `prev` | hex de 64 caracteres | hash del registro anterior; en el primero, `GENESIS_HASH` |
| `hash` | hex de 64 caracteres | SHA-256 del registro (ver §3) |

El paquete (bundle) añade metadatos de exportación:

```json
{
  "format": "aegistrace.evidence.v1",
  "orgId": "org-acme",
  "incidentId": "inc_…",
  "generatedAt": "2024-06-01T09:30:00.000Z",
  "generatedBy": "root-admin",
  "sources": ["events", "alerts", "analyses", "activity"],
  "missing": [],
  "head": "<hash del último registro>",
  "entries": 16,
  "records": [ … ]
}
```

- `head` y `entries` son **afirmaciones**: el verificador las recalcula y compara. No se confía en ellas.
- `missing` lista las referencias que el incidente todavía cita pero que ya no existen (por ejemplo, eventos borrados por retención). Nunca se oculta una pérdida.
- `generatedAt` y `generatedBy` no forman parte de la cadena: dos exportaciones del mismo estado tienen los mismos `records` y el mismo `head`.

## 2. Orden

Los registros se ordenan con una relación de orden total, independiente del idioma del sistema:

1. `at`, comparado como cadena (válido porque todas las fechas son ISO-8601 UTC del mismo formato);
2. `kind`: `event` < `alert` < `analysis` < `activity`;
3. `refs[0]`;
4. `summary`.

## 3. Cálculo del hash

1. Se toma el registro **sin** el campo `hash`, con `seq` y `prev` incluidos.
2. Se serializa en **JSON canónico**:
   - las claves de cada objeto se ordenan por código UTF-16 (orden por defecto de JavaScript);
   - sin espacios;
   - los miembros con valor `undefined` se omiten; en arrays se conserva el orden;
   - cadenas y números con `JSON.stringify`.
3. `hash = SHA-256(bytes UTF-8 de la serialización)`, en hexadecimal minúsculas.

Ejemplo de canonicalización: `{"b":1,"a":{"d":[3,{"y":1,"x":undefined}]}}` → `{"a":{"d":[3,{"y":1}]},"b":1}`.

`GENESIS_HASH` son 64 ceros.

## 4. Verificación (algoritmo)

Para `i` desde 1 hasta `n` (esperado `seq = i`, `prev_esperado` empieza en `GENESIS_HASH`):

1. Si el registro no es un objeto con `seq` numérico y `prev`/`hash` de texto → **`malformed`** en `i`.
2. Si `seq ≠ i` → **`seq_gap`** en `i` (hay borrados, huecos o reordenaciones).
3. Si `prev ≠ prev_esperado` → **`genesis_mismatch`** (si `i = 1`) o **`prev_mismatch`** en `i`.
4. Si `SHA-256(canónico(registro sin hash)) ≠ hash` → **`hash_mismatch`** en `i`.
5. `prev_esperado ← hash`.

Al final, si el paquete declara `head` y `entries` distintos de los calculados → **`claimed_head_mismatch`**.

Con un **ancla** (`head` y `entries` publicados fuera del sistema) se compara también el resultado → **`anchor_mismatch`**.

El resultado es `{ valid, entries, head, brokenAt?, reason? }`. `brokenAt` es el `seq` del primer registro que falla.

## 5. Cómo verificar

Sin servidor, sin claves, con Node.js instalado:

```bash
cd api && npm ci
npm run verify-evidence -- ../docs/examples/evidence-bundle.json
npm run verify-evidence -- ../docs/examples/evidence-bundle.tampered.json   # FAIL: hash_mismatch en seq 4
```

Con ancla (recomendado para cualquier uso real):

```bash
npm run verify-evidence -- bundle.json --anchor-head <head publicado> --anchor-entries <n>
```

Códigos de salida: `0` válido, `1` no válido, `2` uso incorrecto. Cuidado al encadenar con tuberías: el código de salida es el de la última orden, no el del verificador.

El mismo verificador se usa en las pruebas (`api/test/forensic.test.ts`), que además comprueban el ejemplo versionado.

## 6. Qué detecta y qué no

| Alteración | Detectada sin ancla | Detectada con ancla |
|---|---|---|
| Editar cualquier campo de un registro (incluido un valor anidado en `data`) | sí, `hash_mismatch` | sí |
| Borrar un registro del medio | sí, `seq_gap` | sí |
| Reordenar registros | sí, `seq_gap` | sí |
| Cambiar `prev` de un registro | sí, `prev_mismatch` / `genesis_mismatch` | sí |
| Editar un registro **y recalcular solo su hash** | sí, en el siguiente (`prev_mismatch`) | sí |
| Borrar los últimos registros (truncado) | **no** | sí, `anchor_mismatch` |
| Editar y **recalcular toda la cadena** | **no** | sí, `anchor_mismatch` |
| Cambiar `head` o `entries` en el paquete | sí, `claimed_head_mismatch` | sí |

**Límite fundamental.** La cadena es pública y no requiere secreto: quien pueda escribir el paquete puede recalcularlo entero. Por eso la integridad frente a un atacante depende de **publicar el `head` y `entries` fuera de su alcance** en el momento de la exportación (un registro de solo anexado, un sistema de log remoto, un bucket con bloqueo de objetos, o incluso una captura en un canal de terceros). Sin ancla, el paquete demuestra coherencia interna, no antigüedad ni autoría.

La auditoría del sistema (`/audit`) usa otro mecanismo: una cadena HMAC con clave secreta, cuyo ancla también puede configurarse con `AEGIS_AUDIT_ANCHOR_FILE`. Las dos cadenas son independientes; esta es la que se entrega a quien investiga.

## 7. Versionado

El identificador `aegistrace.evidence.v1` fija este formato. Un cambio incompatible en la canonicalización, en el orden o en los campos requiere una versión nueva (`v2`) y el verificador debe rechazar identificadores que no conozca. Los paquetes v1 seguirán verificándose con la misma regla.

## 8. Datos personales

Los paquetes contienen IPs, usuarios y, en `event.data.attrs`, el texto libre de los logs. Tratan como datos sensibles: quien los exporta debe tener el rol `auditor` o `admin` (cada exportación queda en la auditoría del sistema) y la política de retención de la organización aplica también a los paquetes que se hayan descargado.
