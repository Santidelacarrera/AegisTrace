# ADR 0003 – La IA recomienda; las personas aprueban

**Estado:** aceptada

**Decisión.**
1. El análisis solo produce texto estructurado (`Analysis`, `Recommendation`); no tiene acceso a la capa de acciones.
2. Todo resultado de un proveedor pasa por `validateAnalysis`: cada ID citado debe pertenecer a los eventos del incidente y hipótesis/recomendaciones deben citar al menos uno. Si no, se descarta con 502 y se audita.
3. Las acciones nacen `pending_approval`, solo existen en modo simulado, se limitan a un ámbito de laboratorio y las aprueba una persona distinta de quien las propuso.
4. Los logs son datos: el proveedor determinista no lee texto libre; cualquier proveedor LLM deberá recibir los eventos como datos delimitados.

**Consecuencias.** Un LLM mal comportado puede producir recomendaciones erróneas pero verificables, no acciones. La validación no comprueba que la cita *respalde* la afirmación, solo que exista y pertenezca al incidente.
