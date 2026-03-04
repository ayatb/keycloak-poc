package org.idyatech.keycloak.spiffe;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.client.FederatedJWTClientAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.DynamicClientRegisteredContext;
import org.keycloak.services.clientregistration.*;
import org.keycloak.services.managers.ClientManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.utils.StringUtil;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Client Registration Provider that uses JWT-SVID as software statement
 * for Dynamic Client Registration (DCR).
 *
 * <p>This provider validates the JWT-SVID signature using the SPIFFE bundle endpoint
 * configured in the identity provider, and extracts client metadata from the JWT claims.</p>
 */
public class SpiffeClientRegistrationProvider extends AbstractClientRegistrationProvider {

    private static final Logger logger = Logger.getLogger(SpiffeClientRegistrationProvider.class);

    private final JwtSvidValidator jwtSvidValidator;

    public SpiffeClientRegistrationProvider(KeycloakSession session) {
        super(session);
        this.jwtSvidValidator = new JwtSvidValidator(session);
    }

    @POST
    @Path("register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createSPIFFECLIENT(ClientRepresentation client) {
        try {
            DefaultClientRegistrationContext context = new DefaultClientRegistrationContext(session, client, this);
            ClientRepresentation clientRep = context.getClient();

            // Ensure attributes map is not null
            Map<String, String> attributes = clientRep.getAttributes();
            if (attributes == null) {
                attributes = new HashMap<>();
                clientRep.setAttributes(attributes);
            }

            // Get the software statement (JWT-SVID) from the request
            String softwareStatement = attributes.get("software_statement");

            if (StringUtil.isBlank(softwareStatement)) {
                logger.error("No software_statement provided in the registration request");
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity("software_statement is required")
                    .build();
            }

            // Get the IDP alias from the request
            String idpAlias = attributes.get("idp_alias");

            logger.infof("Received software statement: %s...",
                    softwareStatement.substring(0, Math.min(50, softwareStatement.length())));

            // Parse and validate the softwareStatement as a JWT-SVID
            JWSInput jwtSvid = jwtSvidValidator.parse(softwareStatement);
            JsonWebToken claims = jwtSvidValidator.validate(jwtSvid, idpAlias);

            if (claims == null) {
                logger.error("Invalid JWT-SVID signature or claims");
                return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Invalid JWT-SVID")
                    .build();
            }

            // Extract SPIFFE ID from the 'sub' claim
            String spiffeId = claims.getSubject();
            logger.infof("SPIFFE ID from JWT-SVID: %s", spiffeId);

            // Set client ID based on SPIFFE ID (extract the last part)
            String clientId = extractClientIdFromSpiffeId(spiffeId);
            clientRep.setClientId(clientId);

            // Set client name
            if (clientRep.getName() == null) {
                clientRep.setName("SPIFFE Client: " + clientId);
            }

            // Set client authentication to use SPIFFE JWT Bearer
            clientRep.setClientAuthenticatorType(FederatedJWTClientAuthenticator.PROVIDER_ID);

            // Enable service accounts (for client_credentials grant)
            clientRep.setServiceAccountsEnabled(true);
            clientRep.setPublicClient(false);

            // Store the SPIFFE ID and IDP alias as attributes
            attributes.put("jwt.credential.sub", spiffeId);
            attributes.put("jwt.credential.issuer", idpAlias);

            // Remove temporary attributes that are not needed in the client
            attributes.remove("software_statement");
            attributes.remove("idp_alias");

            // Set the audience from JWT claims
            String[] audience = claims.getAudience();
            if (audience != null && audience.length > 0) {
                attributes.put("spiffe.audience", String.join(",", audience));
            }

            logger.infof("Creating client with ID: %s for SPIFFE ID: %s", clientId, spiffeId);
            create(context);

            URI uri = session.getContext().getUri().getAbsolutePathBuilder().path(clientRep.getClientId()).build();
            return Response.created(uri).entity(clientRep).build();

        } catch (ModelDuplicateException e) {
            logger.warnf("Client already exists: %s", e.getMessage());
            throw ErrorResponse.error("Client already exists", Response.Status.CONFLICT);
        } catch (Exception e) {
            logger.error("Error during SPIFFE client registration", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity("Registration failed: " + e.getMessage())
                .build();
        }
    }

    @Override
    public ClientRepresentation create(ClientRegistrationContext context) {
        ClientRepresentation client = context.getClient();
        if (client.getOptionalClientScopes() != null && client.getDefaultClientScopes() == null) {
            client.setDefaultClientScopes(List.of(OIDCLoginProtocolFactory.BASIC_SCOPE));
        }

        event.event(EventType.CLIENT_REGISTER);

        try {
            RealmModel realm = session.getContext().getRealm();

            // Check if client already exists
            ClientModel existingClient = realm.getClientByClientId(client.getClientId());
            if (existingClient != null) {
                event.detail(Details.REASON, "client_exists");
                throw new ModelDuplicateException("Client with SPIFFE ID already exists: " + client.getClientId());
            }

            ClientModel clientModel = ClientManager.createClient(session, realm, client);

            if (clientModel.isServiceAccountsEnabled()) {
                new ClientManager(new RealmManager(session)).enableServiceAccount(clientModel);
            }

            if (Boolean.TRUE.equals(client.getAuthorizationServicesEnabled())) {
                RepresentationToModel.createResourceServer(clientModel, session, true);
            }

            session.getContext().setClient(clientModel);
            session.clientPolicy().triggerOnEvent(new DynamicClientRegisteredContext(context, clientModel, auth.getJwt(), realm));

            client = ModelToRepresentation.toRepresentation(clientModel, session);
            client.setSecret(clientModel.getSecret());
            client.setDirectAccessGrantsEnabled(clientModel.isDirectAccessGrantsEnabled());

            event.client(client.getClientId()).success();
            return client;
        } catch (ClientPolicyException cpe) {
            event.detail(Details.REASON, Details.CLIENT_POLICY_ERROR);
            event.detail(Details.CLIENT_POLICY_ERROR, cpe.getError());
            event.detail(Details.CLIENT_POLICY_ERROR_DETAIL, cpe.getErrorDetail());
            event.error(cpe.getError());
            throw new ErrorResponseException(cpe.getError(), cpe.getErrorDetail(), Response.Status.BAD_REQUEST);
        }
    }

    /**
     * Extract a client ID from the SPIFFE ID.
     * Example: spiffe://localhost.idyatech.fr/mcp-client → mcp-client
     *
     * @param spiffeId the full SPIFFE ID URI
     * @return the last path segment, or "unknown-client" if parsing fails
     */
    private String extractClientIdFromSpiffeId(String spiffeId) {
        if (spiffeId == null || !spiffeId.startsWith("spiffe://")) {
            return "unknown-client";
        }

        int lastSlash = spiffeId.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < spiffeId.length() - 1) {
            return spiffeId.substring(lastSlash + 1);
        }

        return "unknown-client";
    }
}
