# Seguridad

## Cómo informar de una vulnerabilidad

Usa los **avisos de seguridad privados de GitHub** del repositorio (pestaña *Security → Report a vulnerability*). No abras un issue público con detalles explotables. Incluye versión o commit, pasos para reproducirlo e impacto.

## Alcance y garantías

AegisTrace es un proyecto de laboratorio/portfolio, no un producto auditado (la licencia [Apache-2.0](LICENSE) lo ofrece sin garantías). El análisis de amenazas, lo que está cubierto y los riesgos residuales conocidos están en [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). No se ha realizado una auditoría ni un pentest independientes.

## Buenas prácticas ya aplicadas

- Secretos obligatorios en producción (el servidor no arranca con credenciales demo).
- RBAC en el servidor, aislamiento por organización, auditoría encadenada con ancla externa.
- Dependencias auditadas en el CI (`npm audit`, `pip-audit`).
