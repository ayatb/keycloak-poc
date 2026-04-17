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

### 3. Real-Time Event Analytics with Kafka, ClickHouse & Metabase

A POC demonstrating how to stream every Keycloak authentication event into a high-performance analytics pipeline and visualise it in real time using Metabase dashboards.

**Key Features:**
- Native Kafka event listener (no polling, no external connector)
- ClickHouse as an OLAP metrics store — sub-second aggregations over millions of events
- Metabase interactive dashboards with date-range and realm filters
- Automated realm provisioning and Kafka listener activation via the Admin REST API
- Realistic multi-realm traffic simulation (PKCE, refresh token, client credentials flows)
- End-to-end pipeline bootstrapped with a single `docker compose up`

👉 **[Go to Real-Time Event Analytics Guide](./keycloak-reporting/README.md)**

**Quick Start:**
```bash
# Add Keycloak hostname to /etc/hosts (once)
echo "127.0.0.1  localhost.idyatech.fr" | sudo tee -a /etc/hosts

cd keycloak-reporting
docker compose up --build
```

| Service | URL | Credentials |
|---|---|---|
| Keycloak | https://localhost.idyatech.fr:8443 | admin / admin |
| Metabase dashboard | http://localhost:3000 | admin@keycloak.local / Admin123! |
| Kafka UI | http://localhost:8080 | — |
| ClickHouse HTTP API | http://localhost:8123 | default / clickhouse |

---

### 4. JWT Authorization Grant – AI Agent Identity Propagation

A POC demonstrating how an **AI Agent** can exchange a corporate JWT token for an access token in a target realm using the **JWT Authorization Grant** (`urn:ietf:params:oauth:grant-type:jwt-bearer`), propagating user identity without exposing credentials.

**Key Features:**
- PKCE-based authentication on the corporate IdP
- Token exchange via JWT Authorization Grant (RFC 7523)
- User identity propagation without re-authentication
- No credential exposure to the target realm
- Standards-based, interoperable, and auditable

👉 **[Go to JWT Authorization Grant Guide](./keycloak-JWT-authorization-grant/README.md)**

**Quick Start:**
```bash
cd keycloak-JWT-authorization-grant
docker compose up --build
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
├── keycloak-reporting/           # Real-Time Event Analytics POC
│   ├── README.md                 # Complete guide
│   ├── docker-compose.yml        # Full stack (Keycloak + Kafka + ClickHouse + Metabase)
│   ├── keycloak/                 # Extensions: keycloak-kafka.jar, dataset.jar
│   ├── clickhouse/
│   │   └── init.sql              # Kafka engine + MergeTree + Materialized Views
│   ├── dataset-loader/
│   │   └── loader.py             # Realm/client/user provisioner + Kafka listener setup
│   ├── traffic-simulator/
│   │   └── simulator.py          # Multi-realm authentication traffic generator
│   └── metabase/
│       └── setup_dashboard.py    # Metabase auto-configurator (connection + dashboard)
└── README.md                     # This file
```

## Prerequisites (All POCs)

- Docker and Docker Compose (v2+)
- ~4 GB disk space (keycloak-reporting requires more due to ClickHouse + Kafka volumes)
- Java 17+ and Maven 3.6+ (for keycloak-spiffe-dcr only)
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
- **JWT:** https://jwt.ioD
- **Kafka Listener:** https://github.com/SnuK87/keycloak-kafka
- **Generating datasets:** https://www.keycloak.org/keycloak-benchmark/dataset-guide/latest/using-provider
