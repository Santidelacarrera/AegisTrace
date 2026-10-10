# ADR 0006 – Autenticación: contraseñas locales, tokens firmados y claves de servicio

**Estado:** aceptada

**Decisión.** Personas: `POST /auth/login` (organización, usuario, contraseña) con scrypt y sal por usuario; devuelve un token `payload.HMAC` con caducidad (por defecto 8 h). En cada petición el usuario se vuelve a buscar en la configuración, de modo que eliminarlo revoca sus sesiones aunque el token no haya caducado. Cinco fallos en 15 minutos bloquean el par organización/usuario; el error es idéntico para usuario inexistente y contraseña errónea. Fallos y éxitos se auditan. Servicios (ingesta): claves API estáticas, con rol `ingestor`.

**Consecuencias.** Suficiente para un laboratorio o un equipo pequeño. No hay SSO, MFA, rotación de claves de firma ni lista de revocación por token; el bloqueo es en memoria (por instancia) y permite bloquear a un usuario legítimo con intentos deliberados. Para producción real se recomienda delegar en un IdP (OIDC) y mantener este mecanismo solo para cuentas de servicio.
