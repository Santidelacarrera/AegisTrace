# ADR 0004 – Auditoría encadenada con HMAC

**Estado:** aceptada

**Decisión.** Cada entrada incluye `prevHash` y `hash = HMAC(clave, campos ‖ prevHash)`, con una cadena por organización. `verify` recalcula la cadena. Se auditan lecturas de incidentes, búsquedas, denegaciones, propuestas, aprobaciones y ejecuciones.

**Ancla externa.** Con `AEGIS_AUDIT_ANCHOR_FILE`, cada entrada añade una línea `org seq hash` a un archivo aparte, y `verify` compara la cadena con la última línea de la organización (también acepta `?anchorHead=&anchorEntries=`).

**Consecuencias.** Detecta edición y borrado intermedio por quien no tenga la clave, y el truncado del final solo si el ancla está fuera del alcance de la aplicación (otro host, almacenamiento de solo anexado); con el archivo en el mismo disco escribible solo detecta errores, no a un atacante con acceso al sistema. Quien tenga la clave HMAC y acceso al almacén puede reescribir la cadena; en producción el rol de la aplicación no debería poder modificar ni borrar filas de auditoría.
