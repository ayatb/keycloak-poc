# JWT Authorization Grant – AI Agent Identity Propagation

## Overview

This proof of concept demonstrates how an **AI Agent** can obtain an access token from a target realm (`ai-agents`) by presenting a JWT issued by a trusted external Identity Provider (`corporate` realm), using the **JWT Authorization Grant** flow (`urn:ietf:params:oauth:grant-type:jwt-bearer`).

The AI agent **never** sees or handles user credentials for the target realm. Instead, it leverages a corporate token as an assertion to prove the user's identity.

---

## Architecture

| Component          | Role                                                        |
|--------------------|-------------------------------------------------------------|
| **Keycloak**       | Hosts both realms (`corporate` and `ai-agents`)             |
| **corporate realm**| Acts as the external corporate Identity Provider             |
| **ai-agents realm**| The target realm that trusts the corporate IdP via JWT Authorization Grant |
| **ai-agent**       | A Python script simulating an AI agent that performs the token exchange |

---

## Sequence Diagram

```
title JWT Authorization Grant – AI Agent Flow

participant User
participant AI Agent
participant Corporate IdP\n(Keycloak corporate realm)
participant AI Platform\n(Keycloak ai-agents realm)
participant Protected Resource\n(MCP Server, API, etc.)

User->AI Agent: 1. Request access to a protected resource

Note over AI Agent: The AI Agent needs a token\nfor the ai-agents realm.\nIt redirects the user to\nthe corporate IdP.

AI Agent->User: 2. Redirect to Corporate IdP login\n(Authorization Code + PKCE)

User->Corporate IdP\n(Keycloak corporate realm): 3. Authenticate (or SSO session already exists)
Note over Corporate IdP\n(Keycloak corporate realm): If the user already has\nan active SSO session,\nno login form is shown.

Corporate IdP\n(Keycloak corporate realm)->User: 4. Redirect back with authorization code
User->AI Agent: 5. Forward authorization code

AI Agent->Corporate IdP\n(Keycloak corporate realm): 6. POST /token (code + code_verifier)
Corporate IdP\n(Keycloak corporate realm)->AI Agent: 7. Corporate Access Token (JWT)

Note over AI Agent: The AI Agent now holds\na corporate JWT with the\nuser's identity.\nNo ai-agents credentials needed.

AI Agent->AI Platform\n(Keycloak ai-agents realm): 8. POST /token\ngrant_type=urn:ietf:params:oauth:grant-type:jwt-bearer\nassertion=<corporate JWT>\nclient_id=ai-agent & client_secret=***

Note over AI Platform\n(Keycloak ai-agents realm): Validate JWT signature (JWKS)\nVerify issuer & audience\nMatch user via federated identity\nIssue new token

AI Platform\n(Keycloak ai-agents realm)->AI Agent: 9. AI-Agents Access Token (JWT)

AI Agent->Protected Resource\n(MCP Server, API, etc.): 10. Access resource with AI-Agents token\nAuthorization: Bearer <token>
Protected Resource\n(MCP Server, API, etc.)->AI Agent: 11. Response (data)

AI Agent->User: 12. Return result to user

Note over User,Protected Resource\n(MCP Server, API, etc.): ✓ The user's identity was propagated\nfrom the Corporate IdP to the AI Platform\nwithout re-authentication or credential exposure.
```

> 💡 You can render this diagram at [websequencediagrams.com](https://www.websequencediagrams.com/) by pasting the content above.

---

## How It Works

### Step 1 – Corporate Authentication (PKCE)

The AI agent authenticates the user against the **corporate** realm using the standard **Authorization Code Flow with PKCE**:

1. Initiates an authorization request with a PKCE `code_challenge`
2. Submits the user's credentials (`ayat` / `password`) to the login form
3. Receives an authorization code
4. Exchanges the code (with `code_verifier`) for a **corporate access token**

The corporate `account` client includes an **audience mapper** that adds the `ai-agents` realm as an audience (`aud`) in the token — this is required for the JWT Authorization Grant to work.

### Step 2 – JWT Authorization Grant (Token Exchange)

The AI agent then calls the **ai-agents** realm token endpoint with:

| Parameter       | Value                                              |
|-----------------|-----------------------------------------------------|
| `grant_type`    | `urn:ietf:params:oauth:grant-type:jwt-bearer`       |
| `assertion`     | The corporate access token (JWT)                     |
| `client_id`     | `ai-agent`                                           |
| `client_secret` | *(confidential client secret)*                       |
| `scope`         | `openid`                                             |

Keycloak validates the assertion by:
1. **Verifying the JWT signature** using the corporate realm's JWKS endpoint
2. **Checking the issuer** matches the configured trusted IdP
3. **Matching the user** via the federated identity link
4. **Issuing a new access token** for the `ai-agents` realm

---

## Advantages of JWT Authorization Grant

### 🔐 No Credential Exposure
The user's credentials are **only** submitted to the corporate IdP. The AI agent realm (`ai-agents`) never sees, stores, or processes any user password. This is a fundamental security improvement over approaches like resource owner password grant.

### 🔄 Identity Propagation Without Re-Authentication
The user authenticates **once** on the corporate IdP. The AI agent can then propagate that identity to the target realm without requiring the user to log in again. This enables seamless **cross-realm** and **cross-domain** identity federation.

### 🤖 Perfect for Machine-to-Machine with User Context
Unlike `client_credentials` (which provides only a service identity), the JWT Authorization Grant carries the **full user identity** through the token chain. This means:
- The AI agent acts **on behalf of the user**
- Audit logs in the target realm trace back to the **actual user**
- Fine-grained authorization policies can be applied based on the user's roles and attributes

### 🏗️ Standards-Based & Interoperable
Built on top of **RFC 7521** and **RFC 7523**, this flow is not vendor-specific. Any OAuth 2.0 compliant authorization server that supports JWT bearer assertions can participate in this pattern.

### 📦 Decoupled Realms / Authorization Servers
The corporate IdP and the AI agents realm are **completely independent**. They don't share databases, sessions, or secrets. The only link is:
- The **JWKS URL** for signature validation
- The **issuer** claim for trust verification
- A **federated identity** mapping in the target realm

### 🔗 Token Chain Traceability
Each token in the chain is independently verifiable. The corporate token and the AI agents token are both standard JWTs with clear `iss`, `sub`, and `aud` claims, providing full auditability.

### 🚀 Scalable for Multi-Agent Architectures
In an AI platform with multiple agents, each agent can independently exchange corporate tokens for realm-specific tokens. There is no shared session state, making this approach highly scalable and stateless.

---

## Running the Demo

```bash
cd keycloak-JWT-authorization-grant
docker compose up --build
```

Keycloak will start, import both realms, and once healthy, the `ai-agent` container will execute the full flow and print detailed logs showing each step, the raw tokens, and decoded JWT claims.

---

## Pre-configured Resources

### Corporate Realm
- **Client**: `account` (public, PKCE-enabled, with audience mapper for `ai-agents`)
- **User**: `ayat` / `password`

### AI-Agents Realm
- **Client**: `ai-agent` (confidential, JWT Authorization Grant enabled)
- **Identity Provider**: `jwt-authorization-grant` (trusts the corporate realm issuer, validates via JWKS)
- **Federated User**: `ayat` (linked to the corporate user via federated identity)

---

## References

- **RFC 7521** – Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants  
  https://datatracker.ietf.org/doc/html/rfc7521

- **RFC 7523** – JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants  
  https://datatracker.ietf.org/doc/html/rfc7523

- **Keycloak Documentation** – JWT Authorization Grant  
  https://www.keycloak.org/securing-apps/jwt-authorization-grant

