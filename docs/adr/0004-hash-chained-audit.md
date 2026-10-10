# ADR 0004 – Auditoría encadenada con HMAC

**Estado:** aceptada

**Decisión.** Cada entrada incluye `prevHash` y `hash = HMAC(clave, campos ‖ prevHash)`, con una cadena por organización. `verify` recalcula la cadena. Se auditan lecturas de incidentes, búsquedas, denegaciones, propuestas, aprobaciones y ejecuciones.

**Consecuencias.** Detecta edición y borrado intermedio por quien no tenga la clave. No detecta el truncado del final: para eso `verify` devuelve `head` y `entries` que deben anclarse externamente y se pueden comparar con `anchorHead`/`anchorEntries`. Quien tenga la clave HMAC y acceso al almacén puede reescribir la cadena; en producción el rol de la aplicación no debería poder modificar ni borrar filas de auditoría.
