# ADR 0006 – Autenticación: contraseña + TOTP, SSO OIDC y claves de servicio

**Estado:** aceptada (ampliada)

**Personas, local.** `POST /auth/login` (organización, usuario, contraseña) con scrypt y sal por usuario. Si el usuario tiene `totpSecret`, también exige un código TOTP (RFC 6238, SHA-1, 30 s, ±1 paso); un código ya usado se rechaza. La respuesta `mfa_required` solo aparece **después** de acertar la contraseña, para no revelar qué usuarios tienen MFA. Devuelve un token `payload.HMAC` con caducidad (8 h por defecto). El usuario se vuelve a buscar en cada petición, de modo que eliminarlo revoca sus sesiones. Cinco fallos (contraseña o código) en 15 minutos bloquean el par organización/usuario; el error es idéntico para usuario inexistente y credencial errónea. Todo se audita.

**Personas, SSO.** OIDC con código de autorización + PKCE (S256), `state` de un solo uso y `nonce`. El `id_token` se verifica contra el JWKS del IdP (firma, emisor, audiencia, caducidad, nonce). Los grupos del IdP se traducen a roles con `OIDC_ROLE_MAP` y gana el rol de mayor privilegio; **sin grupo mapeado no hay acceso** (no existe rol por defecto). La sesión resultante es un token con el rol embebido y caducidad corta (1 h), entregado a la UI en el fragmento de la URL (`#token=`), que nunca se envía a un servidor.

**Servicios.** Claves API estáticas con rol `ingestor`.

**Consecuencias.** Suficiente para un laboratorio o equipo pequeño. Los usuarios locales se gestionan editando configuración; no hay recuperación de contraseña ni códigos de recuperación de MFA. Una sesión SSO no se puede revocar antes de caducar (salvo rotando la clave de firma). SSO probado solo contra un IdP simulado; falta validarlo con un proveedor real. Sin SAML.
