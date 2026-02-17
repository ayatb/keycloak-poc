// main.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"
	"os"
	"os/exec"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)
const (
	socketPath = "unix:///opt/spire/sockets/agent.sock"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

    // Create client options to set the expected socket path,
    // as default sources will use the value from the SPIFFE_ENDPOINT_SOCKET env var.
    clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))

	// 1. Connect to the SPIRE Workload API (via the Unix socket).
	// The socket address is read from the SPIFFE_ENDPOINT_SOCKET env var.
	source, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Impossible de se connecter à SPIRE: %w", err)
	}
	defer source.Close()

	// 2. Define the audience for the JWT (the token recipient).
	audience := os.Getenv("AUDIENCE")
	if audience == "" {
        audience = "https://localhost.idyatech.fr:8443/auth/realms/spiffe" // default value
    }

	// 3. Fetch the JWT-SVID.
	svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		log.Fatalf("Erreur lors de la récupération du JWT-SVID: %v", err)
	}

	fmt.Printf("JWT-SVID récupéré avec succès !\n\n%s\n", svid.Marshal())
	// Export the JWT-SVID to an env var so other processes can use it.
    err = os.Setenv("JWT_SVID", svid.Marshal())

    // Exchange the JWT-SVID for an access token from Keycloak using curl.
    cmd := exec.Command("curl",
        "-X", "POST",
        "-H", "Content-Type:application/x-www-form-urlencoded",
        "-d", "grant_type=client_credentials",
        "-d", "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
        "-d", fmt.Sprintf("client_assertion=%s", svid.Marshal()),
        "-k",
        "-v",
        "-w", "\nHTTP Status: %{http_code}\n",
        "https://keycloak:8443/auth/realms/spiffe/protocol/openid-connect/token")

    // Execute the curl command and print the response.
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Fatalf("Erreur lors de l'appel à Keycloak: %v\nOutput: %s", err, output)
    }
    fmt.Printf("Réponse de Keycloak:\n%s\n", output)
}