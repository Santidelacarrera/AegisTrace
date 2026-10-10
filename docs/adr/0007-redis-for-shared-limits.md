# ADR 0007 – Redis solo para límites compartidos

**Estado:** aceptada

**Contexto.** La propuesta pedía Redis/BullMQ "si hace falta". El rate limiting y el bloqueo de login en memoria dejan de ser válidos al ejecutar más de una instancia: cada una contaría por separado.

**Decisión.** Una interfaz `Limiter` (`hit`/`peek`/`reset`) con implementación en memoria y otra en Redis (INCR + PEXPIRE atómicos con un script Lua, ventana fija). La API usa Redis si hay `REDIS_URL`. Si Redis falla, degrada a memoria local y lo registra en el log, en lugar de rechazar peticiones. **No se usa BullMQ:** detección y análisis son síncronos y rápidos y no hay trabajo diferido que lo justifique.

**Consecuencias.** Los límites son globales entre instancias (probado con dos instancias y Redis real). El estado de dominio sigue siendo local a cada proceso (ADR 0002), así que esto no basta por sí solo para escalar horizontalmente. Ventana fija: permite ráfagas de hasta el doble en el cambio de ventana.
