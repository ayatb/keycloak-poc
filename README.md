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

## Getting Started

Each POC is self-contained in its own directory with:
- Complete documentation (README.md)
- Docker Compose setup
- Source code and configurations
- Step-by-step guides and troubleshooting

Select a POC above and follow the guide in its README for full instructions.

## Repository Structure

```
keycloak-poc/
├── keycloak-spiffe/          # Secret-less Auth POC
│   ├── README.md             # Complete guide
│   ├── docker-compose.yml    # Services orchestration
│   ├── keycloak/             # Keycloak realm config
│   ├── spire-server/         # SPIRE Server config
│   ├── spire-agent/          # SPIRE Agent config
│   ├── oidc-discovery-provider/  # OIDC config
│   └── workload/             # Sample Go client
└── README.md                 # This file
```

## Prerequisites (All POCs)

- Docker and Docker Compose (v2+)
- Basic familiarity with Keycloak and identity management concepts