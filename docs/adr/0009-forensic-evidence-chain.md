# ADR 0009 – Evidencia forense: cadena SHA-256 pública con ancla externa

**Estado:** aceptada · *Nexus Security & AI Lab*

**Contexto.** Hace falta entregar a quien investiga la evidencia de un incidente y que pueda comprobar, sin acceso al sistema, que no se ha alterado. La auditoría interna ya usa HMAC con clave secreta, que no sirve para terceros.

**Decisión.** Un paquete (`aegistrace.evidence.v1`) con registros ordenados por tiempo y encadenados por SHA-256 sobre JSON canónico. No usa clave: cualquiera puede verificarlo. El verificador recalcula todo y nunca confía en los hashes ni en `head`/`entries` declarados. La protección frente a truncado y recálculo completo se obtiene publicando `head` y `entries` fuera del sistema (`--anchor-head`, `--anchor-entries`).

**Alternativas descartadas.**
- *HMAC con la clave de auditoría:* impide la verificación por terceros.
- *Firmas asimétricas por registro:* añaden gestión de claves sin cerrar el problema del recálculo completo, que el ancla ya resuelve.
- *Árbol de Merkle:* permitiría probar pertenencia de un registro sin el paquete completo; se deja para cuando haya exportaciones grandes.

**Consecuencias.** Detecta edición, borrado, reordenación y cambio de enlaces (ver tabla en `docs/EVIDENCE-FORMAT.md`). Sin ancla no detecta truncado ni recálculo completo; el documento lo dice expresamente. Los paquetes contienen datos personales: la exportación está restringida a auditor y admin y queda auditada.
