# ADR 0002 – Almacén en memoria con persistencia write-through a PostgreSQL

**Estado:** aceptada (revisada; reemplaza la versión "solo memoria")

**Contexto.** Se quería validar el flujo y los permisos antes de invertir en un modelo relacional, pero perder los datos al reiniciar impedía usar el sistema.

**Decisión.** `Store.org(orgId)` sigue siendo el único acceso a datos y el conjunto de trabajo vive en memoria. Con `DATABASE_URL`, `PgPersistence` (a) recarga todo al arrancar y (b) antes de enviar cualquier respuesta a una petición autenticada, escribe los documentos que cambiaron (JSONB, por hash de contenido) y las nuevas entradas de auditoría (tabla aparte, solo inserciones). Si la escritura falla, la respuesta es 500. El esquema usado está en `api/migrations/`; `db/schema.sql` es el diseño relacional objetivo.

**Rendimiento.** Los eventos (inmutables) se insertan por lotes de 500 y no se vuelven a procesar; el resto de colecciones se comparan por hash de contenido. Medido en local contra PostgreSQL 16: ~250 ms → ~18 ms por lote de 500 eventos con 6 000 en memoria; ~35 ms con 30 000 (la detección sigue siendo O(n) por ingesta).

**Consecuencias.** Sobrevive a reinicios (probado contra PostgreSQL 16, incluida la deduplicación y la cadena de auditoría). Pero: cada petición recorre las colecciones de la organización, solo hay una instancia posible (dos procesos pisarían el estado), una caída entre la mutación en memoria y la escritura deja memoria y disco distintos hasta reiniciar, y no hay RLS. Evolución natural: repositorio relacional con transacciones por petición.
