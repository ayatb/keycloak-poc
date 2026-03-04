// main.go
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	socketPath = "unix:///opt/spire/sockets/agent.sock"
)

// httpClient creates an HTTP client that skips TLS verification (dev/POC only).
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// dcrRequest represents the Dynamic Client Registration request payload.
type dcrRequest struct {
	ClientID             string            `json:"clientId,omitempty"`
	Description          string            `json:"description,omitempty"`
	DefaultClientScopes  []string          `json:"defaultClientScopes,omitempty"`
	Attributes           map[string]string `json:"attributes,omitempty"`
}

// tokenResponse represents the Keycloak token endpoint response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

func main() {
	fmt.Println("=========================================")
	fmt.Println("SPIFFE Dynamic Client Registration Test")
	fmt.Println("=========================================")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "https://keycloak:8443"
	}

	realm := os.Getenv("REALM")
	if realm == "" {
		realm = "spiffe"
	}

	audience := os.Getenv("AUDIENCE")
	if audience == "" {
		audience = keycloakURL + "/auth/realms/" + realm
	}

	idpAlias := os.Getenv("IDP_ALIAS")
	if idpAlias == "" {
		idpAlias = "spiffe"
	}

	// =========================================================================
	// Step 1: Fetch JWT-SVID from SPIRE Agent
	// =========================================================================
	fmt.Println("Step 1: Fetching JWT-SVID from SPIRE Agent...")
	fmt.Printf("  Audience: %s\n", audience)

	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))
	source, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		log.Fatalf("❌ Failed to connect to SPIRE Agent: %v", err)
	}
	defer source.Close()

	svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		log.Fatalf("❌ Failed to fetch JWT-SVID: %v", err)
	}

	jwtToken := svid.Marshal()
	fmt.Println("✅ JWT-SVID obtained successfully!")
	fmt.Printf("  SPIFFE ID: %s\n", svid.ID.String())
	fmt.Printf("  JWT (first 80 chars): %s...\n\n", jwtToken[:min(80, len(jwtToken))])

	// =========================================================================
	// Step 2: Register client via Dynamic Client Registration
	// =========================================================================
	fmt.Println("Step 2: Registering client via Dynamic Client Registration...")

	dcrEndpoint := fmt.Sprintf("%s/auth/realms/%s/clients-registrations/spiffe-dcr/register", keycloakURL, realm)
	fmt.Printf("  DCR Endpoint: %s\n", dcrEndpoint)

	reqBody := dcrRequest{
		Description:         "Client registered via SPIFFE DCR with JWT-SVID",
		DefaultClientScopes: []string{"mcp:resources", "mcp:tools", "mcp:prompts"},
		Attributes: map[string]string{
			"software_statement": jwtToken,
			"idp_alias":         idpAlias,
		},
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		log.Fatalf("❌ Failed to marshal DCR request: %v", err)
	}

	fmt.Printf("  Request payload:\n")
	prettyPrint(bodyJSON)
	fmt.Println()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dcrEndpoint, bytes.NewReader(bodyJSON))
	if err != nil {
		log.Fatalf("❌ Failed to create DCR request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := httpClient()
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("❌ Failed to call DCR endpoint: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("❌ Failed to read DCR response: %v", err)
	}

	fmt.Printf("  Response (HTTP %d):\n", resp.StatusCode)
	prettyPrint(respBody)
	fmt.Println()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		// If client already exists (409 Conflict), continue to step 3 anyway
		if resp.StatusCode == http.StatusConflict {
			fmt.Println("⚠️  Client already exists, continuing to authentication step...")
		} else {
			log.Fatalf("❌ Client registration failed with status %d", resp.StatusCode)
		}
	} else {
		fmt.Println("✅ Client registered successfully!")

		var dcrResp map[string]interface{}
		if err := json.Unmarshal(respBody, &dcrResp); err == nil {
			fmt.Printf("  Client ID:  %v\n", dcrResp["clientId"])
			fmt.Printf("  UUID:       %v\n", dcrResp["id"])
			if attrs, ok := dcrResp["attributes"].(map[string]interface{}); ok {
				fmt.Printf("  SPIFFE ID:  %v\n", attrs["jwt.credential.sub"])
			}
		}
	}

	fmt.Println()

	// =========================================================================
	// Step 3: Authenticate with the registered client using JWT-SVID
	// =========================================================================
	fmt.Println("Step 3: Testing authentication with registered client...")

	tokenEndpoint := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", keycloakURL, realm)
	fmt.Printf("  Token Endpoint: %s\n", tokenEndpoint)

	// Fetch a truly fresh JWT-SVID for the token exchange (new source to avoid cache)
	fmt.Println("  Fetching fresh JWT-SVID...")
	freshSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		log.Fatalf("❌ Failed to create fresh JWT source: %v", err)
	}
	defer freshSource.Close()

	freshSvid, err := freshSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		log.Fatalf("❌ Failed to fetch fresh JWT-SVID: %v", err)
	}
	freshToken := freshSvid.Marshal()
	fmt.Printf("  Fresh JWT-SVID fetched at: %s\n", time.Now().UTC().Format(time.RFC3339))

	// Build and send token request immediately after fetching the fresh SVID
	formData := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"},
		"client_assertion":      {freshToken},
	}

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		log.Fatalf("❌ Failed to create token request: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	fmt.Printf("  Sending token request at: %s\n", time.Now().UTC().Format(time.RFC3339))
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		log.Fatalf("❌ Failed to call token endpoint: %v", err)
	}
	defer tokenResp.Body.Close()

	tokenRespBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		log.Fatalf("❌ Failed to read token response: %v", err)
	}

	fmt.Printf("  Response (HTTP %d):\n", tokenResp.StatusCode)
	prettyPrint(tokenRespBody)
	fmt.Println()

	var token tokenResponse
	if err := json.Unmarshal(tokenRespBody, &token); err == nil {
		if token.AccessToken != "" {
			fmt.Println("✅ Authentication successful!")
			fmt.Printf("  Token type:  %s\n", token.TokenType)
			fmt.Printf("  Expires in:  %d seconds\n", token.ExpiresIn)
			fmt.Printf("  Scope:       %s\n", token.Scope)
			fmt.Printf("  Access token (first 80 chars): %s...\n", token.AccessToken[:min(80, len(token.AccessToken))])
		} else {
			fmt.Printf("⚠️  Authentication failed: %s - %s\n", token.Error, token.ErrorDesc)
		}
	}

	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("Test completed!")
	fmt.Println("=========================================")
}

// prettyPrint formats JSON bytes for display.
func prettyPrint(data []byte) {
	var out bytes.Buffer
	if err := json.Indent(&out, data, "    ", "  "); err != nil {
		fmt.Printf("    %s\n", string(data))
		return
	}
	for _, line := range strings.Split(out.String(), "\n") {
		fmt.Printf("    %s\n", line)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

