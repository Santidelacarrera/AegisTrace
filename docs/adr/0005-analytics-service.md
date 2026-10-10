# ADR 0005 – Servicio de analítica separado (FastAPI), opcional y fail-open

**Estado:** aceptada

**Decisión.** Un servicio Python independiente recibe eventos normalizados (solo id, hora, tipo, usuario, IP) y devuelve anomalías estadísticas: picos de fallos por usuario (z-score robusto con mediana/MAD) y login desde una IP nunca vista. La API lo llama tras cada ingesta con un timeout de 3 s; si falla, se registra y la detección por reglas continúa. La API descarta IDs de evento que el servicio invente y vuelve a asignar severidad ella misma. Las anomalías entran por el mismo camino que las reglas (alertas, correlación, auditoría).

**Medición.** Sobre datos sintéticos etiquetados no supera a las reglas (precisión 0.73 dev / 0.43 holdout en `rate_spike`; 0 en `new_source_ip`). Por eso `new_source_ip` es *signal-only* (nunca crea incidentes) y las alertas estadísticas son de severidad media/baja.

**Consecuencias.** Aporta una segunda opinión y una frontera de despliegue clara, pero hoy es más complejidad que valor medido. Se mantiene por ser la pieza prevista en la arquitectura y porque permite sustituir detectores sin tocar la API; habría que reevaluarlo con datos reales.
