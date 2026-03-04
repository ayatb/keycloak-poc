# keycloak-poc

This repository contains multiple Proof of Concept (POC) projects demonstrating various Keycloak and identity management patterns and integrations.

## Available POCs

### 1. Secret-less Authentication with Keycloak and SPIFFE/SPIRE

A POC demonstrating how to authenticate applications without exposing static secrets, using SPIFFE/SPIRE for dynamic identity generation.

**Key Features:**
- Cryptographic proof of identity (JWT-SVID)
- No static secrets to manage or rotate
- Automatic revocation and rotation via SPIRE
- Complete audit trail

👉 **[Go to Secret-less Authentication Guide](./keycloak-spiffe/README.md)**

**Quick Start:**
```bash
cd keycloak-spiffe
docker compose up -d --build
```

---

### 2. SPIFFE Dynamic Client Registration (DCR)

A Keycloak extension that enables **Dynamic Client Registration** using **JWT-SVID** as a software statement, allowing SPIFFE workloads to register themselves as OAuth2/OIDC clients without any pre-configuration.

**Key Features:**
- On-the-fly client registration using JWT-SVID as software statement
- Full cryptographic signature verification against SPIFFE bundle endpoint
- Client auto-configured with `federated-jwt` authenticator and service accounts
- Default client scopes support (e.g. `mcp:resources`, `mcp:tools`, `mcp:prompts`)
- Duplicate client detection (409 Conflict)

👉 **[Go to SPIFFE DCR Guide](./keycloak-spiffe-dcr/README.md)**

**Quick Start:**
```bash
cd keycloak-spiffe-dcr
mvn clean package
# JAR is automatically mounted in Keycloak via the keycloak-spiffe docker-compose.yml
```

---

## Getting Started

Each POC is self-contained in its own directory with:
- Complete documentation (README.md)
- Docker Compose setup or Maven build
- Source code and configurations
- Step-by-step guides and troubleshooting

Select a POC above and follow the guide in its README for full instructions.

## Repository Structure

```
keycloak-poc/
├── keycloak-spiffe/              # Secret-less Auth POC
│   ├── README.md                 # Complete guide
│   ├── docker-compose.yml        # Services orchestration
│   ├── keycloak/                 # Keycloak realm config
│   ├── spire-server/             # SPIRE Server config
│   ├── spire-agent/              # SPIRE Agent config
│   ├── oidc-discovery-provider/  # OIDC config
│   └── workload/                 # Go client (DCR + token exchange)
├── keycloak-spiffe-dcr/          # SPIFFE DCR Keycloak Extension
│   ├── README.md                 # Complete guide
│   ├── pom.xml                   # Maven config (Keycloak 26.5.3, Java 17)
│   └── src/main/java/            # Provider & Validator implementation
│       └── org/idyatech/keycloak/spiffe/
│           ├── SpiffeClientRegistrationProviderFactory.java
│           ├── SpiffeClientRegistrationProvider.java
│           └── JwtSvidValidator.java
└── README.md                     # This file
```

## Prerequisites (All POCs)

- Docker and Docker Compose (v2+)
- ~2 GB disk space
- Java 17+ and Maven 3.6+ (for keycloak-spiffe-dcr)
- Basic familiarity with Keycloak and identity management concepts

## Contributing

Feel free to extend this repository with additional POCs. When adding a new POC:

1. Create a new directory with a descriptive name
2. Include a comprehensive `README.md`
3. Add the POC to the list above
4. Ensure all configuration and source files are included

## Resources

- **Keycloak:** https://www.keycloak.org
- **SPIFFE/SPIRE:** https://spiffe.io
- **OIDC:** https://openid.net/connect/
- **JWT:** https://jwt.io
