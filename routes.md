# README - Contrato de Rotas do Backend (NavalhaHub)

## 1. Objetivo

Este documento define apenas o contrato HTTP das rotas que o backend precisa expor para o frontend:

- metodo e path
- autenticacao
- headers obrigatorios
- body (request)
- response de sucesso
- status codes e erros padrao

Base path sugerida: `/api/v1`

---

## 2. Convencoes globais

## 2.1 Headers padrao (request)

Enviar em todas as chamadas:

- `Content-Type: application/json` (exceto upload multipart)
- `Accept: application/json`
- `X-Request-Id: <uuid-opcional>`

Para sessao via cookie HttpOnly:

- frontend deve usar `credentials: include`
- nao enviar bearer token no frontend para fluxos normais

Para rotas com CSRF (mutacoes sensiveis):

- `X-CSRF-Token: <token>`

## 2.2 Formato padrao de erro

```json
{
  "error": {
    "code": "STRING_CODE",
    "message": "Mensagem legivel",
    "details": {}
  }
}
```

## 2.3 Status padrao

- `200` OK (consulta e mutacao sem criacao)
- `201` Created
- `204` No Content
- `400` Bad Request
- `401` Unauthorized
- `403` Forbidden
- `404` Not Found
- `409` Conflict
- `422` Unprocessable Entity
- `429` Too Many Requests
- `500` Internal Server Error

---

## 3. Auth e Sessao

## 3.1 Login

- Metodo: `POST`
- Path: `/api/v1/auth/login`
- Auth: publica

Headers:

- `Content-Type: application/json`
- `Accept: application/json`

Body:

```json
{
  "email": "user@email.com",
  "password": "string"
}
```

Sucesso `200`:

```json
{
  "user": {
    "id": "uuid",
    "email": "user@email.com",
    "mfaEnabled": true
  }
}
```

Erros:

- `401` `INVALID_CREDENTIALS`
- `423` `ACCOUNT_LOCKED`
- `429` `RATE_LIMITED`

Observacao:

- backend deve setar cookies HttpOnly (`access`/`refresh` ou cookie de sessao unico).

## 3.2 Signup

- Metodo: `POST`
- Path: `/api/v1/auth/signup`
- Auth: publica

Body:

```json
{
  "email": "user@email.com",
  "password": "string",
  "fullName": "Nome"
}
```

Sucesso `201`:

```json
{
  "user": {
    "id": "uuid",
    "email": "user@email.com"
  },
  "requiresEmailVerification": true
}
```

Erros:

- `409` `EMAIL_ALREADY_IN_USE`
- `422` `WEAK_PASSWORD`

## 3.3 Usuario logado (sessao atual)

- Metodo: `GET`
- Path: `/api/v1/auth/me`
- Auth: cookie de sessao

Sucesso `200`:

```json
{
  "user": {
    "id": "uuid",
    "email": "user@email.com",
    "role": "owner",
    "mfaEnabled": true
  }
}
```

Erros:

- `401` `UNAUTHORIZED`

## 3.4 Logout

- Metodo: `POST`
- Path: `/api/v1/auth/logout`
- Auth: cookie de sessao

Sucesso `204` sem body

## 3.5 Password reset request

- Metodo: `POST`
- Path: `/api/v1/auth/password/reset-request`
- Auth: publica

Body:

```json
{
  "email": "user@email.com"
}
```

Sucesso `200`:

```json
{
  "ok": true
}
```

## 3.6 Password reset confirm

- Metodo: `POST`
- Path: `/api/v1/auth/password/reset-confirm`
- Auth: publica

Body:

```json
{
  "token": "reset-token",
  "newPassword": "string"
}
```

Sucesso `200`:

```json
{
  "ok": true
}
```

Erros:

- `400` `TOKEN_INVALID`
- `400` `TOKEN_EXPIRED`

---

## 4. MFA

## 4.1 Listar fatores

- Metodo: `GET`
- Path: `/api/v1/auth/mfa/factors`
- Auth: cookie de sessao

Sucesso `200`:

```json
{
  "factors": [
    {
      "id": "factor-id",
      "type": "totp",
      "status": "verified"
    }
  ]
}
```

## 4.2 Iniciar enrollment

- Metodo: `POST`
- Path: `/api/v1/auth/mfa/enroll`
- Auth: cookie de sessao

Body:

```json
{
  "friendlyName": "NavalhaHub"
}
```

Sucesso `200`:

```json
{
  "factorId": "factor-id",
  "qrCode": "otpauth://...",
  "secret": "BASE32SECRET"
}
```

## 4.3 Challenge

- Metodo: `POST`
- Path: `/api/v1/auth/mfa/challenge`
- Auth: cookie de sessao

Body:

```json
{
  "factorId": "factor-id"
}
```

Sucesso `200`:

```json
{
  "challengeId": "challenge-id"
}
```

## 4.4 Verify

- Metodo: `POST`
- Path: `/api/v1/auth/mfa/verify`
- Auth: cookie de sessao

Body:

```json
{
  "factorId": "factor-id",
  "challengeId": "challenge-id",
  "code": "123456"
}
```

Sucesso `200`:

```json
{
  "ok": true,
  "aal": "aal2"
}
```

Erros:

- `400` `INVALID_OTP`
- `403` `MFA_REQUIRED`

---

## 5. Booking publico e agendamentos

## 5.1 Dados publicos da barbearia para booking

- Metodo: `GET`
- Path: `/api/v1/public/booking/:slug`
- Auth: publica

Sucesso `200`:

```json
{
  "barbershop": {
    "id": "uuid",
    "name": "Barbearia X",
    "description": "...",
    "logoUrl": "https://...",
    "primaryColor": "#000000",
    "secondaryColor": "#ffffff"
  },
  "barbers": [],
  "services": []
}
```

Erros:

- `404` `BARBERSHOP_NOT_FOUND`

## 5.2 Disponibilidade publica

- Metodo: `GET`
- Path: `/api/v1/public/availability`
- Auth: publica

Query params:

- `barberId` (obrigatorio)
- `date` (obrigatorio, `YYYY-MM-DD`)
- `serviceId` (opcional)

Sucesso `200`:

```json
{
  "slots": ["09:00", "09:30", "10:00"]
}
```

## 5.3 Criar agendamento

- Metodo: `POST`
- Path: `/api/v1/appointments`
- Auth: publica (fluxo publico) ou autenticada (painel)

Body:

```json
{
  "barbershopId": "uuid",
  "barberId": "uuid",
  "serviceId": "uuid",
  "appointmentDate": "2026-08-12",
  "appointmentTime": "14:00",
  "customerName": "Nome",
  "customerPhone": "+5511999999999",
  "customerEmail": "x@email.com",
  "notes": "texto opcional"
}
```

Sucesso `201`:

```json
{
  "appointmentId": "uuid",
  "managementToken": "token",
  "status": "confirmed"
}
```

Erros:

- `409` `SLOT_UNAVAILABLE`
- `422` `INVALID_INPUT`
- `429` `RATE_LIMITED`

## 5.4 Buscar agendamento por token de gerenciamento

- Metodo: `GET`
- Path: `/api/v1/appointments/manage/:token`
- Auth: publica com token

Sucesso `200`:

```json
{
  "appointment": {
    "id": "uuid",
    "status": "confirmed",
    "appointmentDate": "2026-08-12",
    "appointmentTime": "14:00"
  }
}
```

Erros:

- `400` `TOKEN_INVALID`
- `400` `TOKEN_EXPIRED`
- `404` `TOKEN_NOT_FOUND`

## 5.5 Cancelar agendamento

- Metodo: `POST`
- Path: `/api/v1/appointments/:id/cancel`
- Auth: cookie de sessao OU token de gerenciamento

Headers adicionais quando usar token:

- `X-Management-Token: <token>`

Body:

```json
{
  "reason": "Cliente nao pode comparecer"
}
```

Sucesso `200`:

```json
{
  "ok": true,
  "status": "cancelled"
}
```

Erros:

- `400` `CANCELLATION_TOO_LATE`
- `400` `TOKEN_INVALID`
- `409` `APPOINTMENT_ALREADY_CANCELLED`

## 5.6 Remarcar agendamento

- Metodo: `POST`
- Path: `/api/v1/appointments/:id/reschedule`
- Auth: cookie de sessao OU token de gerenciamento

Headers adicionais quando usar token:

- `X-Management-Token: <token>`

Body:

```json
{
  "newDate": "2026-08-20",
  "newTime": "15:30",
  "newBarberId": "uuid-opcional",
  "newServiceId": "uuid-opcional"
}
```

Sucesso `200`:

```json
{
  "ok": true,
  "newAppointmentId": "uuid"
}
```

Erros:

- `409` `SLOT_UNAVAILABLE`
- `400` `TOKEN_INVALID`

---

## 6. Billing

## 6.1 Status da assinatura

- Metodo: `GET`
- Path: `/api/v1/billing/subscription`
- Auth: cookie de sessao

Sucesso `200`:

```json
{
  "subscribed": true,
  "plan": "pro",
  "productId": "prod_xxx",
  "subscriptionEnd": "2026-12-31T00:00:00.000Z"
}
```

## 6.2 Criar checkout

- Metodo: `POST`
- Path: `/api/v1/billing/checkout`
- Auth: cookie de sessao

Body:

```json
{
  "priceId": "price_xxx"
}
```

Sucesso `200`:

```json
{
  "url": "https://checkout.stripe.com/..."
}
```

## 6.3 Portal do cliente

- Metodo: `POST`
- Path: `/api/v1/billing/portal`
- Auth: cookie de sessao

Sucesso `200`:

```json
{
  "url": "https://billing.stripe.com/..."
}
```

## 6.4 Checkout operacional de atendimento

- Metodo: `POST`
- Path: `/api/v1/checkout/finalize`
- Auth: cookie de sessao

Body:

```json
{
  "appointmentId": "uuid",
  "paymentMethod": "pix",
  "servicePrice": 50,
  "productsTotal": 20,
  "discount": 0,
  "finalAmount": 70,
  "cart": [
    {
      "productId": "uuid",
      "quantity": 1,
      "unitPrice": 20
    }
  ]
}
```

Sucesso `200`:

```json
{
  "ok": true,
  "alreadyProcessed": false,
  "transactionId": "uuid"
}
```

Erros:

- `409` `ALREADY_PROCESSED`
- `422` `INVALID_CART`

---

## 7. CRUD operacional (painel)

Todos autenticados via cookie de sessao.

## 7.1 Products

- `GET /api/v1/products?barbershopId=<uuid>`
- `POST /api/v1/products`
- `PUT /api/v1/products/:id`
- `DELETE /api/v1/products/:id`

Body create/update exemplo:

```json
{
  "barbershopId": "uuid",
  "name": "Pomada",
  "price": 39.9,
  "stock": 10
}
```

## 7.2 Services

- `GET /api/v1/services?barbershopId=<uuid>`
- `POST /api/v1/services`
- `PUT /api/v1/services/:id`
- `DELETE /api/v1/services/:id`

## 7.3 Customers

- `GET /api/v1/customers?barbershopId=<uuid>`
- `POST /api/v1/customers`
- `PUT /api/v1/customers/:id`
- `DELETE /api/v1/customers/:id`

## 7.4 Expenses

- `GET /api/v1/expenses?barbershopId=<uuid>`
- `POST /api/v1/expenses`
- `PUT /api/v1/expenses/:id`
- `DELETE /api/v1/expenses/:id`

## 7.5 Barbers e commissions

- `GET /api/v1/barbers?barbershopId=<uuid>`
- `POST /api/v1/barbers`
- `PUT /api/v1/barbers/:id`
- `DELETE /api/v1/barbers/:id`
- `GET /api/v1/commissions?barbershopId=<uuid>`
- `POST /api/v1/commissions`
- `PUT /api/v1/commissions/:id`
- `DELETE /api/v1/commissions/:id`

---

## 8. Dashboard e analytics

## 8.1 KPIs dashboard

- Metodo: `GET`
- Path: `/api/v1/dashboard/kpis?barbershopId=<uuid>&start=<YYYY-MM-DD>&end=<YYYY-MM-DD>`
- Auth: cookie de sessao

Sucesso `200`:

```json
{
  "totalRevenue": 10000,
  "totalAppointments": 300,
  "avgTicket": 33.3
}
```

## 8.2 Revenue series

- `GET /api/v1/dashboard/revenue-series?barbershopId=<uuid>&days=30`

## 8.3 WhatsApp stats

- `GET /api/v1/dashboard/whatsapp-stats?barbershopId=<uuid>`

---

## 9. Integracao WhatsApp/MegaAPI

## 9.1 Salvar configuracao da integracao

- Metodo: `POST`
- Path: `/api/v1/integrations/whatsapp/config`
- Auth: cookie de sessao

Body:

```json
{
  "barbershopId": "uuid",
  "instanceKey": "string",
  "token": "string"
}
```

Sucesso `200`:

```json
{
  "ok": true
}
```

## 9.2 Testar credenciais

- Metodo: `POST`
- Path: `/api/v1/integrations/whatsapp/test`
- Auth: cookie de sessao

Body:

```json
{
  "instanceKey": "string",
  "token": "string"
}
```

Sucesso `200`:

```json
{
  "success": true,
  "message": "Conexao OK"
}
```

## 9.3 Envio de mensagem (uso interno)

- Metodo: `POST`
- Path: `/api/v1/integrations/whatsapp/send`
- Auth: service-to-service ou role interna (nao expor para browser)

---

## 10. Auditoria e observabilidade

## 10.1 Registrar evento de auditoria

- Metodo: `POST`
- Path: `/api/v1/audit/events`
- Auth: cookie de sessao

Body:

```json
{
  "action": "appointment_created",
  "level": "info",
  "description": "Agendamento criado",
  "metadata": {
    "appointmentId": "uuid"
  }
}
```

Sucesso `201`:

```json
{
  "id": "uuid"
}
```

## 10.2 Health publico simplificado

- Metodo: `GET`
- Path: `/api/v1/health`
- Auth: publica

Sucesso `200`:

```json
{
  "status": "ok",
  "timestamp": "2026-08-12T00:00:00.000Z"
}
```

---

## 11. CORS, cookies e seguranca

Backend deve garantir:

- `Access-Control-Allow-Origin` com allowlist explicita.
- `Access-Control-Allow-Credentials: true`.
- cookies com `HttpOnly`, `Secure`, `SameSite=Lax` (ou `Strict` se possivel).
- rate limit em login, signup, booking publico, reset password.
- validacao de payload em todas as rotas (schema).
- autorizacao por tenant/barbershop em rotas autenticadas.

---

## 12. Lista minima de entrega (MVP backend)

Se quiser iniciar com o minimo para o frontend atual funcionar:

1. Auth

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/signup`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`
- `POST /api/v1/auth/password/reset-request`
- `POST /api/v1/auth/password/reset-confirm`

2. Booking

- `GET /api/v1/public/booking/:slug`
- `GET /api/v1/public/availability`
- `POST /api/v1/appointments`
- `GET /api/v1/appointments/manage/:token`
- `POST /api/v1/appointments/:id/cancel`
- `POST /api/v1/appointments/:id/reschedule`

3. Billing

- `GET /api/v1/billing/subscription`
- `POST /api/v1/billing/checkout`
- `POST /api/v1/billing/portal`
- `POST /api/v1/checkout/finalize`

4. WhatsApp

- `POST /api/v1/integrations/whatsapp/config`
- `POST /api/v1/integrations/whatsapp/test`

5. Operacional base

- `GET/POST/PUT/DELETE /api/v1/products`
- `GET/POST/PUT/DELETE /api/v1/services`
- `GET/POST/PUT/DELETE /api/v1/customers`
