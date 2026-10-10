# ADR 0001 – Reglas deterministas antes que modelos

**Estado:** aceptada

**Contexto.** Los equipos pequeños necesitan alertas que puedan reproducir y explicar. Un modelo opaco dificulta confiar en una alerta y evaluar falsos positivos.

**Decisión.** La detección es una función pura `detect(events) → candidatos` con umbrales explícitos (`RULE_CONFIG`). Los IDs de alertas e incidentes se derivan por hash de su contenido, de modo que los mismos eventos dan los mismos IDs. Cada alerta incluye una explicación con el umbral aplicado.

**Consecuencias.** Reproducible y fácil de probar; los umbrales son frágiles ante evasión lenta (p. ej. fallos espaciados > 5 min no alertan). Un servicio de anomalías (FastAPI) podrá complementar, no sustituir, estas reglas.
