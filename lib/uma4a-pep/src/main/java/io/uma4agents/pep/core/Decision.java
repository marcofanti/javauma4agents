package io.uma4agents.pep.core;

import java.util.List;
import java.util.Map;

/**
 * A verdict, plus everything a host needs to render it. How it reaches the client is the
 * host's business: a gateway turns a challenge into 401 + WWW-Authenticate; the embedded
 * vault turns it into a JSON-RPC error carrying the same ticket and as_uri.
 *
 * @param outcome what happened
 * @param status HTTP status for the gateway envelope
 * @param error OAuth-style error code
 * @param description human-readable reason, may be empty
 * @param ticket UMA permission ticket (challenge only)
 * @param asUri the authorization server the agent should go to
 * @param resourceMetadata RFC 9728 metadata URL
 * @param scopes scopes the request needed
 * @param authorizationDetails RFC 9396 details of the missing authority
 * @param authorizationReference content address of {@code authorizationDetails}
 * @param family negotiation family of the grant (allow only)
 * @param contract contract reference of the grant (allow only)
 */
public record Decision(Outcome outcome, int status, String error, String description,
                       String ticket, String asUri, String resourceMetadata,
                       List<String> scopes, List<Map<String, Object>> authorizationDetails,
                       String authorizationReference, String family, String contract) {

    /** The three verdicts. */
    public enum Outcome { ALLOW, CHALLENGE, DENY }

    public static final Decision ALLOW =
            new Decision(Outcome.ALLOW, 200, "", "", null, null, null, null, null, null, null,
                    null);

    public static Decision deny(int status, String error, String description) {
        return new Decision(Outcome.DENY, status, error, description, null, null, null, null,
                null, null, null, null);
    }

    static Decision allowed(String family, String contract) {
        return new Decision(Outcome.ALLOW, 200, "", "", null, null, null, null, null, null,
                family, contract);
    }

    static Decision awaitingOwner(String asUri, String resourceMetadata) {
        return new Decision(Outcome.DENY, 503, "authorization_pending",
                "this resource server has registered with the owner's authorization server "
                        + "and is waiting for her to authorize it",
                null, asUri, resourceMetadata, null, null, null, null, null);
    }

    static Decision challenge(String ticket, String asUri, String resourceMetadata,
                              List<String> scopes, List<Map<String, Object>> details,
                              String reference) {
        return new Decision(Outcome.CHALLENGE, 401, "uma_challenge", "", ticket, asUri,
                resourceMetadata, scopes, details, reference, null, null);
    }

    /** The same verdict naming a different RFC 9728 metadata URL. */
    public Decision withResourceMetadata(String url) {
        return new Decision(outcome, status, error, description, ticket, asUri, url, scopes,
                authorizationDetails, authorizationReference, family, contract);
    }

    public boolean allowed() {
        return outcome == Outcome.ALLOW;
    }
}
