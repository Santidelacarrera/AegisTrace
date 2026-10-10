# ADR 0002 – Almacén en memoria para el MVP

**Estado:** aceptada (temporal)

**Contexto.** Se quería validar el flujo completo y el modelo de permisos antes de invertir en persistencia.

**Decisión.** `Store.org(orgId)` es el único punto de acceso a datos y devuelve estructuras de esa organización. Un repositorio PostgreSQL mantendría esa firma (esquema objetivo en `db/schema.sql`, con `organization_id` en todas las claves y `CHECK` de `mode='simulated'` y de no auto-aprobación).

**Consecuencias.** Los datos se pierden al reiniciar y no hay escalado horizontal. Pendiente: implementar el repositorio SQL, migraciones y RLS opcional.
