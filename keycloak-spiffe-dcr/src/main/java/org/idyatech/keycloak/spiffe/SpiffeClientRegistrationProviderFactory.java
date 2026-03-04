package org.idyatech.keycloak.spiffe;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;
import org.keycloak.services.clientregistration.ClientRegistrationProviderFactory;

/**
 * Factory for the SPIFFE Client Registration Provider
 */
public class SpiffeClientRegistrationProviderFactory implements ClientRegistrationProviderFactory {

    public static final String PROVIDER_ID = "spiffe-dcr";

    @Override
    public ClientRegistrationProvider create(KeycloakSession session) {
        return new SpiffeClientRegistrationProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // No initialization needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization needed
    }

    @Override
    public void close() {
        // No cleanup needed
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}

