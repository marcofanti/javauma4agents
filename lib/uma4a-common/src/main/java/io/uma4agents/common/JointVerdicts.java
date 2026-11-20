package io.uma4agents.common;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Recounts signed holder verdicts and checks what they actually cover. */
public final class JointVerdicts {
    private JointVerdicts() {}

    @FunctionalInterface
    public interface Keys {
        List<Map<String, Object>> read(String issuer, boolean refresh);
    }

    public static Map<String, Object> verify(String token, JointMandate.Holder holder,
                                              Keys keys, double now) {
        var parsed = CompactJws.parse(token);
        if (!"u4a-verdict+jwt".equals(parsed.header().get("typ"))) {
            return Map.of();
        }
        Object kid = parsed.header().get("kid");
        for (boolean fresh : List.of(false, true)) {
            for (Map<String, Object> key : keys.read(holder.issuer(), fresh)) {
                if (kid != null && !kid.equals(key.get("kid"))) {
                    continue;
                }
                try {
                    Map<String, Object> claims = CompactJws.verify(token, Jwks.toPublicKey(key)).claims();
                    PyJwtClaims.validateWithIat(claims, now, "exp", "iat");
                    if (holder.issuer().equals(claims.get("iss"))
                            && holder.owner().equals(claims.get("holder"))) {
                        return claims;
                    }
                } catch (IllegalArgumentException | SecurityException invalid) {
                    // The next key can be the one that signed during rotation.
                }
            }
        }
        return Map.of();
    }

    public static String checkGrant(Map<String, Object> info, String account, String resource,
                                    JointMandate mandate, Map<String, String> trusted, Keys keys,
                                    double now) {
        return checkGrant(info, account, resource, mandate, trusted, keys, now, 60);
    }

    public static String checkGrant(Map<String, Object> info, String account, String resource,
                                    JointMandate mandate, Map<String, String> trusted, Keys keys,
                                    double now, double clockSkew) {
        Map<String, Object> joint = object(info.get("joint"));
        if (joint.isEmpty()) {
            return "this resource is held jointly, and this grant carries no holders' verdicts to count";
        }
        if (!account.equals(joint.get("account")) || !account.equals(info.get("owner"))) {
            return "the grant names a different jointly held account";
        }
        if (!mandate.governs(resource)) {
            return "the published mandate does not cover this resource";
        }
        for (JointMandate.Holder holder : mandate.holders()) {
            String known = trusted.get(holder.owner());
            if (known == null) {
                return holder.owner() + " holds this resource, and this resource server does not "
                        + "know which authority speaks for them";
            }
            if (!known.equals(holder.issuer())) {
                return "the mandate names " + PyRepr.of(holder.issuer()) + " for " + holder.owner()
                        + ", and this resource server knows them by " + PyRepr.of(known);
            }
        }
        String digest = mandate.digest();
        Map<String, Object> signer = object(object(info.get("cnf")).get("jwk"));
        String thumb = signer.keySet().containsAll(List.of("kty", "crv", "x"))
                ? Jwks.thumbprint(signer) : null;
        Map<String, String> verdicts = new LinkedHashMap<>();
        for (Object candidate : list(joint.get("verdicts"))) {
            if (!(candidate instanceof String token)) {
                return "a verdict in this grant is not a token";
            }
            Object owner;
            try {
                owner = CompactJws.parse(token).claims().get("holder");
            } catch (IllegalArgumentException invalid) {
                return "a verdict in this grant is not a token";
            }
            var holder = owner instanceof String s ? mandate.holder(s) : null;
            if (holder == null) {
                return "a verdict is signed for " + PyRepr.of(owner)
                        + ", who is not a holder of this resource";
            }
            Map<String, Object> claims = verify(token, holder, keys, now);
            if (claims.isEmpty()) {
                return "the verdict attributed to " + holder.owner()
                        + " does not verify against that holder's authority, or has expired";
            }
            if (!java.util.Objects.equals(claims.get("contract"), info.get("contract"))) {
                return holder.owner() + "'s verdict is about a different agreement than "
                        + "this grant was issued for";
            }
            if (!account.equals(claims.get("account"))) {
                return holder.owner() + "'s verdict is about a different jointly held account";
            }
            if (!resource.equals(claims.get("resource_id"))) {
                return holder.owner() + "'s verdict is about a different resource";
            }
            if (!java.util.Objects.equals(claims.get("negotiation"), info.get("family"))) {
                return holder.owner() + "'s verdict is about a different negotiation";
            }
            if (!"allow".equals(claims.get("effect"))) {
                continue;
            }
            if (!digest.equals(claims.get("mandate_s256"))) {
                return holder.owner() + " agreed under a different mandate than the one "
                        + "published for this account";
            }
            String outside = outside(info, resource, claims, thumb, now, clockSkew);
            if (outside != null) {
                return holder.owner() + "'s verdict does not cover this grant: " + outside;
            }
            verdicts.put(holder.owner(), "allow");
        }
        var count = mandate.count(verdicts);
        return "allow".equals(count.effect()) ? null
                : "this grant claims the holders agreed, and the verdicts inside it carry "
                        + count.allowed() + " of the " + count.threshold() + " it takes";
    }

    private static String outside(Map<String, Object> info, String resource,
                                  Map<String, Object> verdict, String thumb, double now, double clockSkew) {
        if (thumb == null || !thumb.equals(verdict.get("cnf_jkt"))) {
            return "it is bound to a different key than the one that agreed";
        }
        List<?> agreed = list(verdict.get("scope"));
        double ends = number(info.get("exp"));
        for (Object item : list(info.get("permissions"))) {
            Map<String, Object> permission = object(item);
            ends = Math.max(ends, number(permission.get("exp")));
            if (resource.equals(permission.get("resource_id"))
                    && !agreed.containsAll(list(permission.get("resource_scopes")))) {
                return "it carries scopes the agreement did not";
            }
        }
        double lifetime = number(verdict.get("expires_in"));
        if (lifetime <= 0) {
            return "the verdict names no agreed lifetime";
        }
        if (ends - now > lifetime + clockSkew) {
            return "it lasts longer than the agreement";
        }
        if (ends > number(verdict.get("exp"))) {
            return "it outlives the holder's verdict";
        }
        Object operation = verdict.get("operation");
        if (operation != null && (!Boolean.TRUE.equals(info.get("single_use"))
                || !operation.equals(info.get("operation")))) {
            return "it is not bound to the one operation that was agreed";
        }
        Integer agreedClass = Consequence.rank(verdict.get("consequence"));
        Integer grantedClass = Consequence.rank(info.get("consequence"));
        if (agreedClass != null && (grantedClass == null || grantedClass < agreedClass)) {
            return "it declares a lighter consequence than the holder answered under";
        }
        return null;
    }

    private static double number(Object value) {
        return value instanceof Number n ? n.doubleValue() : 0;
    }

    private static List<?> list(Object value) {
        return value instanceof List<?> l ? l : List.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        return value instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }
}
