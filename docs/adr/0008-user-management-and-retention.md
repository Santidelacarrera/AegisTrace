# ADR 0008 – Usuarios gestionados por la API y retención de datos

**Estado:** aceptada

**Usuarios.** Además de los usuarios de configuración (`AEGIS_USERS`, solo lectura, pensados para el primer administrador), cada organización puede tener usuarios guardados en la base. Una contraseña temporal (20 caracteres aleatorios) se muestra una sola vez y obliga a cambiarla: mientras tanto el token solo permite `/auth/password` y `/auth/me`. Cambiar o resetear la contraseña, o desactivar al usuario, invalida todos los tokens anteriores mediante `iat` frente a `passwordChangedAt`. El MFA se activa en dos pasos (secreto pendiente + código válido), emite 10 códigos de recuperación de un solo uso (solo se guardan sus hashes) y las semillas TOTP se cifran con AES-256-GCM (`AEGIS_DATA_KEY`). Salvaguardas: nadie puede cambiarse el rol ni desactivarse a sí mismo y siempre debe quedar un administrador activo.

**Retención.** `applyRetention` borra, en este orden, incidentes cerrados vencidos con sus alertas, análisis, recomendaciones y acciones, y después eventos vencidos que ningún incidente o alerta restante cite. La evidencia de incidentes abiertos se conserva sea cual sea su edad. Los borrados se propagan a PostgreSQL en el mismo `flush`. Hay simulación (`dryRun`, por defecto) y cada ejecución se audita. La auditoría no se purga: quitar un prefijo rompería la cadena.

**Consecuencias.** No hay recuperación autoservicio (requeriría correo): el administrador resetea. Las claves `AEGIS_DATA_KEY` y `AEGIS_AUDIT_KEY` no se pueden rotar sin migración. Los usuarios de configuración y los de la API conviven y los de configuración tienen prioridad solo cuando no existe el mismo id en la base (la API impide crear ids repetidos).
