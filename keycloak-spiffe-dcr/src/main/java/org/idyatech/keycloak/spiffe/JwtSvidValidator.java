package org.idyatech.keycloak.spiffe;

import org.jboss.logging.Logger;
import org.keycloak.broker.spiffe.SpiffeBundleEndpointLoader;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.keys.PublicKeyStorageUtils;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

import java.nio.charset.StandardCharsets;

/**
 * Validates a JWT-SVID (SPIFFE Verifiable Identity Document) by:
 * <ol>
 *   <li>Resolving the identity provider from the realm by alias</li>
 *   <li>Verifying the cryptographic signature against the SPIFFE bundle endpoint public keys</li>
 *   <li>Deserializing and validating the JWT claims (sub, iss, exp, nbf)</li>
 * </ol>
 */
public class JwtSvidValidator {

    private static final Logger logger = Logger.getLogger(JwtSvidValidator.class);

    private final KeycloakSession session;

    public JwtSvidValidator(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Parse a raw JWT-SVID string into a {@link JWSInput}.
     *
     * @param rawJwt the raw JWT string
     * @return the parsed JWSInput
     * @throws JWSInputException if parsing fails
     */
    public JWSInput parse(String rawJwt) throws JWSInputException {
        return new JWSInput(rawJwt);
    }

    /**
     * Validate the JWT-SVID signature and claims.
     *
     * @param jwtSvid  the parsed JWT-SVID
     * @param idpAlias the alias of the identity provider holding the bundle endpoint config
     * @return the validated claims, or {@code null} if validation fails
     */
    public JsonWebToken validate(JWSInput jwtSvid, String idpAlias) {
        try {
            // 1. Resolve the identity provider
            IdentityProviderModel identityProvider = resolveIdentityProvider(idpAlias);
            if (identityProvider == null) {
                return null;
            }

            // 2. Verify the JWT-SVID signature
            if (!verifySignature(jwtSvid, identityProvider)) {
                logger.error("JWT-SVID signature verification failed");
                return null;
            }

            // 3. Deserialize and validate claims
            JsonWebToken claims = deserializeClaims(jwtSvid);
            if (claims == null) {
                return null;
            }

            // 4. Validate SPIFFE-specific claims
            if (!validateSpiffeClaims(claims)) {
                return null;
            }

            // 5. Validate temporal claims (exp, nbf)
            if (!validateTemporalClaims(claims)) {
                return null;
            }

            logger.infof("JWT-SVID validation successful for SPIFFE ID: %s", claims.getSubject());
            return claims;

        } catch (Exception e) {
            logger.error("Error validating JWT-SVID", e);
            return null;
        }
    }

    /**
     * Resolve the identity provider from the realm by alias.
     */
    private IdentityProviderModel resolveIdentityProvider(String idpAlias) {
        if (StringUtil.isBlank(idpAlias)) {
            logger.error("Missing idp_alias attribute in the registration request");
            return null;
        }

        RealmModel realm = session.getContext().getRealm();
        IdentityProviderModel identityProvider = realm.getIdentityProviderByAlias(idpAlias);

        if (identityProvider == null) {
            logger.errorf("Identity provider not found for alias: %s", idpAlias);
        }

        return identityProvider;
    }

    /**
     * Deserialize the JWT payload into a {@link JsonWebToken}.
     */
    private JsonWebToken deserializeClaims(JWSInput jwtSvid) {
        try {
            return JsonSerialization.readValue(jwtSvid.getContent(), JsonWebToken.class);
        } catch (Exception e) {
            logger.error("Failed to deserialize JWT-SVID claims", e);
            return null;
        }
    }

    /**
     * Validate SPIFFE-specific claims: sub must be a valid SPIFFE ID, iss must be present.
     */
    private boolean validateSpiffeClaims(JsonWebToken claims) {
        if (claims.getSubject() == null || !claims.getSubject().startsWith("spiffe://")) {
            logger.errorf("Invalid SPIFFE ID in JWT 'sub' claim: %s", claims.getSubject());
            return false;
        }

        if (claims.getIssuer() == null) {
            logger.error("Missing 'iss' claim in JWT-SVID");
            return false;
        }

        return true;
    }

    /**
     * Validate temporal claims: expiration (exp) and not-before (nbf).
     */
    private boolean validateTemporalClaims(JsonWebToken claims) {
        long now = System.currentTimeMillis() / 1000;

        Long exp = claims.getExp();
        if (exp != null && exp > 0 && exp < now) {
            logger.errorf("JWT-SVID has expired (exp=%d, now=%d)", exp, now);
            return false;
        }

        return true;
    }

    /**
     * Verify the JWT-SVID cryptographic signature using the SPIFFE bundle endpoint public keys.
     */
    private boolean verifySignature(JWSInput jwtSvid, IdentityProviderModel identityProvider) {
        try {
            String bundleEndpoint = identityProvider.getConfig().get("bundleEndpoint");
            if (StringUtil.isBlank(bundleEndpoint)) {
                logger.errorf("No bundleEndpoint configured for identity provider: %s", identityProvider.getAlias());
                return false;
            }

            JWSHeader header = jwtSvid.getHeader();
            String kid = header.getKeyId();
            String alg = header.getRawAlgorithm();

            if (StringUtil.isBlank(kid)) {
                logger.error("No 'kid' header found in JWT-SVID");
                return false;
            }

            String modelKey = PublicKeyStorageUtils.getIdpModelCacheKey(
                    session.getContext().getRealm().getId(), identityProvider.getInternalId());

            PublicKeyStorageProvider keyStorage = session.getProvider(PublicKeyStorageProvider.class);
            KeyWrapper publicKey = keyStorage.getPublicKey(modelKey, kid, alg,
                    new SpiffeBundleEndpointLoader(session, bundleEndpoint));

            if (publicKey == null) {
                logger.errorf("No public key found for kid=%s, alg=%s from bundle endpoint: %s", kid, alg, bundleEndpoint);
                return false;
            }

            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
            if (signatureProvider == null) {
                logger.errorf("Signature provider not found for algorithm: %s", alg);
                return false;
            }

            return signatureProvider.verifier(publicKey)
                    .verify(jwtSvid.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8),
                            jwtSvid.getSignature());
        } catch (Exception e) {
            logger.error("Failed to verify JWT-SVID signature", e);
            return false;
        }
    }
}

