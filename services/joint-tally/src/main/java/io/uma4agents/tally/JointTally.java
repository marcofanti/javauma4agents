package io.uma4agents.tally;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.Consequence;
import io.uma4agents.common.EdDsa;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.Jose;
import io.uma4agents.common.JointMandate;
import io.uma4agents.common.JointPeer;
import io.uma4agents.common.JointVerdicts;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.PyJson;
import io.uma4agents.common.PyJwtClaims;
import io.uma4agents.common.S256;
import io.uma4agents.common.SslContexts;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

@RestController
final class JointTally {
    private static final String UMA = "urn:ietf:params:oauth:grant-type:uma-ticket";
    private static final String TERMS = "https://u4a.ai/spec/terms/1.0";
    private static final String FORMAT = TERMS + "#myterms-agreement-v1+jws";
    private static final String CLAIM = TERMS + "#myterms-agreement";
    private static final SecureRandom RANDOM = new SecureRandom();
    private final String issuer = env("TALLY_ISSUER", "https://joint-tally.uma.lab");
    private final String audience = env("TALLY_AUDIENCE", "https://gateway.uma.lab");
    private final String secret = env("TALLY_RS_SECRET", "tally-rs-dev-secret");
    private final String kid = env("TALLY_KID", "tally-1");
    private final int maxOpen = Integer.parseInt(env("TALLY_MAX_OPEN_NEGOTIATIONS", "200"));
    private final long ticketTtl = Long.parseLong(env("TALLY_TICKET_TTL_S", "300"));
    private final long requestTtl = Long.parseLong(env("TALLY_REQUEST_TTL_S", "120"));
    private final int pollInterval = Integer.parseInt(env("TALLY_POLL_INTERVAL", "2"));
    private final KeyPair key = EdDsa.loadOrCreate(Path.of(env("TALLY_SIGNING_KEY", "/keys/tally-ed25519.pem")));
    private final JointPeer peer;
    private final Map<String, JointMandate> mandates = new LinkedHashMap<>();
    private final ConcurrentMap<String, Ticket> tickets = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Negotiation> negotiations = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Template> templates = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Grant> grants = new ConcurrentHashMap<>();
    private final EventLog log = new EventLog("joint-tally");

    private record Ticket(String family, long expires) {}
    private static final class Template {
        final String family;
        final Map<String, Object> wire;
        volatile boolean signed;
        Template(String family, Map<String, Object> wire) {
            this.family = family;
            this.wire = wire;
        }
    }
    private static final class Grant {
        final Map<String, Object> claims;
        boolean spent;
        Grant(Map<String, Object> claims) { this.claims = claims; }
    }
    private static final class Negotiation {
        final String family;
        final String account;
        final String resource;
        final List<?> scopes;
        final Map<String, String> effects = new LinkedHashMap<>();
        final Map<String, List<?>> reasons = new LinkedHashMap<>();
        final Map<String, String> proofs = new LinkedHashMap<>();
        volatile long touched = now();
        volatile String agreement;
        String digest;
        Map<String, Object> contract;
        Map<String, Object> signer;
        Template template;

        Negotiation(String account, String resource, List<?> scopes) {
            this.family = "jnt_" + uuid();
            this.account = account;
            this.resource = resource;
            this.scopes = scopes;
        }
    }

    JointTally(ObjectMapper mapper) throws IOException {
        var http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER);
        String ca = env("UMA4A_CA_BUNDLE", "");
        if (!ca.isBlank()) {
            http.sslContext(SslContexts.fromPem(Path.of(ca)));
        }
        peer = new JointPeer(http.build());
        long floor = Long.parseLong(env("TALLY_THRESHOLD_FLOOR", "0"));
        String raw = env("TALLY_MANDATES", "");
        String file = env("TALLY_MANDATES_FILE", "");
        if (!file.isEmpty() && Files.exists(Path.of(file))) {
            raw = Files.readString(Path.of(file));
        }
        if (!raw.isBlank()) {
            Map<String, Object> entries = mapper.readValue(raw, new TypeReference<>() {});
            entries.forEach((account, doc) -> {
                if (!account.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) {
                    throw new IllegalArgumentException("invalid mandate account " + account);
                }
                mandates.put(account, JointMandate.parse(doc, floor));
            });
        }
    }

    @GetMapping("/health")
    Map<String, Object> health() {
        return Map.of("ok", true, "accounts", mandates.keySet().stream().sorted().toList());
    }

    @GetMapping("/jwks")
    Map<String, Object> jwks() {
        var jwk = Jwks.okpPublicJwk(key.getPublic());
        jwk.putAll(Map.of("kid", kid, "alg", "EdDSA", "use", "sig"));
        return Map.of("keys", List.of(jwk));
    }

    @GetMapping({"/.well-known/uma2-configuration", "/.well-known/uma4agents-configuration"})
    Map<String, Object> configuration() {
        return row("issuer", issuer, "jwks_uri", issuer + "/jwks", "token_endpoint", issuer + "/token",
                "permission_endpoint", issuer + "/perm", "introspection_endpoint", issuer + "/introspect",
                "consume_endpoint", issuer + "/consume", "u4a_tally", true,
                "u4a_mandate_endpoint", issuer + "/mandate/{account}", "response_types_supported",
                List.of(), "grant_types_supported", List.of(UMA), "claim_token_formats_supported",
                List.of(FORMAT), "uma_profiles_supported", List.of("https://u4a.ai/spec/core/1.0",
                        TERMS, "https://u4a.ai/spec/multiparty/1.0"));
    }

    @GetMapping("/mandate/{account}")
    Map<String, Object> mandate(@PathVariable String account) {
        JointMandate mandate = mandates.get(account);
        if (mandate == null) {
            throw error(HttpStatus.NOT_FOUND, "no such mandate");
        }
        var doc = new LinkedHashMap<>(mandate.wire());
        doc.putAll(Map.of("account", account, "tally", issuer, "summary", mandate.describe()));
        return doc;
    }

    @PostMapping("/perm")
    synchronized Map<String, Object> permission(HttpServletRequest request,
                                                @RequestBody Map<String, Object> body) {
        resourceAuth(request);
        String resource = text(body.get("resource_id"));
        String account = mandates.entrySet().stream().filter(e -> e.getValue().governs(resource))
                .map(Map.Entry::getKey).findFirst().orElseThrow(() ->
                        error(HttpStatus.BAD_REQUEST, "no mandate covers that resource"));
        sweep();
        long unsigned = 0;
        long committed = 0;
        for (Negotiation open : negotiations.values()) {
            if (account.equals(open.account)) {
                if (open.agreement == null) {
                    unsigned++;
                } else {
                    committed++;
                }
            }
        }
        if (unsigned >= maxOpen || committed >= maxOpen) {
            throw error(HttpStatus.SERVICE_UNAVAILABLE, "too many negotiations are open over this account");
        }
        var rec = new Negotiation(account, resource, list(body.get("resource_scopes")));
        negotiations.put(rec.family, rec);
        return Map.of("ticket", mint(rec));
    }

    @GetMapping("/terms/{*path}")
    Map<String, Object> terms(@PathVariable String path) {
        Template template = templates.get(path.substring(1));
        if (template == null) {
            throw error(HttpStatus.NOT_FOUND, "no such terms document");
        }
        Map<String, Object> body = new LinkedHashMap<>(template.wire);
        body.remove("family");
        return body;
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    ResponseEntity<Map<String, Object>> token(@RequestParam Map<String, String> form) {
        String grant = form.get("grant_type");
        if ("client_credentials".equals(grant)) {
            return same(secret, form.get("client_secret")) ? reply(200,
                    Map.of("access_token", secret, "token_type", "Bearer", "expires_in", 3600,
                            "scope", "uma_protection")) : refused(401, "invalid_client", null);
        }
        if (!UMA.equals(grant)) {
            return refused(400, "unsupported_grant_type", null);
        }
        Ticket held = tickets.remove(form.getOrDefault("ticket", ""));
        Negotiation rec = held == null || held.expires() < now() ? null : negotiations.get(held.family());
        if (rec == null) {
            return refused(400, "invalid_grant", null);
        }
        rec.touched = now();
        if ("true".equals(form.get("decline"))) {
            negotiations.remove(rec.family);
            return refused(403, "request_denied", null);
        }
        JointMandate mandate = mandates.get(rec.account);
        if (rec.agreement != null) {
            return poll(rec, mandate);
        }
        String agreement = form.get("claim_token");
        if (agreement == null || agreement.isEmpty()) {
            return dictate(rec, mandate);
        }
        if (!FORMAT.equals(form.get("claim_token_format"))) {
            return refused(400, "invalid_claim_token_format", null);
        }
        if (rec.template == null) {
            return refused(400, "invalid_grant", null);
        }
        try {
            byte[] bytes = Jwks.b64urlDecode(agreement);
            String jwt = new String(bytes, StandardCharsets.UTF_8);
            var parsed = CompactJws.parse(jwt);
            var signer = object(parsed.header().get("jwk"));
            if (signer.isEmpty() && parsed.header().get("agent_token") instanceof String token) {
                signer = object(object(CompactJws.parse(token).claims().get("cnf")).get("jwk"));
            }
            Map<String, Object> claims = CompactJws.verifyWith(jwt, Jwks.toPublicKey(signer),
                    Jose.algOf(signer)).claims();
            PyJwtClaims.validateWithAudience(claims, now(), issuer);
            Map<String, Object> template = rec.template.wire;
            if (!template.get("nonce").equals(claims.get("nonce")) || !rec.family.equals(claims.get("family"))
                    || !template.get("template_id").equals(claims.get("template_id"))) {
                return refused(403, "request_denied", "that agreement is not the one proffered");
            }
            rec.digest = S256.of(bytes);
            rec.signer = signer;
            rec.contract = claims;
            rec.agreement = agreement;
            rec.template.signed = true;
        } catch (RuntimeException invalid) {
            negotiations.remove(rec.family);
            return refused(403, "request_denied", invalid.getMessage());
        }
        return poll(rec, mandate);
    }

    private ResponseEntity<Map<String, Object>> dictate(Negotiation rec, JointMandate mandate) {
        List<Map<String, Object>> quotes = new ArrayList<>();
        List<String> quoted = new ArrayList<>();
        for (JointMandate.Holder holder : mandate.holders()) {
            try {
                var response = ask(holder, "/joint/quote", row("owner", holder.owner(),
                        "account", rec.account, "resource_id", rec.resource));
                if (!response.ok()) {
                    throw new IllegalStateException("quote returned HTTP " + response.status());
                }
                var tier = object(response.result().get("tier"));
                if (!tier.isEmpty()) {
                    quotes.add(tier);
                    quoted.add(holder.owner());
                }
            } catch (RuntimeException unavailable) {
                negotiations.remove(rec.family);
                throw error(HttpStatus.SERVICE_UNAVAILABLE, holder.owner()
                        + "'s authority could not be asked for her terms; try again");
            }
        }
        if (quotes.isEmpty()) {
            negotiations.remove(rec.family);
            return refused(403, "request_denied", "no holder of this account has written terms over that resource");
        }
        var folded = JointMandate.fold(quotes, mandate.resources());
        var terms = object(folded.get("terms"));
        List<?> scopes = list(terms.get("scope"));
        String id = rec.account + "/joint/" + rec.family;
        Map<String, Object> template = row("template_id", id, "terms_uri", issuer + "/terms/" + id,
                "proffered_by", issuer, "purpose", "Access to " + rec.account + ", held jointly",
                "scope", scopes.stream().filter(s -> rec.scopes.isEmpty() || rec.scopes.contains(s)).toList(),
                "expires_in", terms.get("expires_in"), "prohibited",
                list(terms.get("prohibited")).stream().map(String::valueOf).sorted().toList(),
                "nonce", random(12), "family", rec.family, "audience", issuer,
                "joint", row("account", rec.account, "tally", issuer, "holders",
                        mandate.holders().stream().map(JointMandate.Holder::owner).toList(),
                        "quoted", quoted, "rule", mandate.kind(), "threshold", mandate.threshold(),
                        "requires", mandate.describe()),
                "enforced", Map.of("ask_me", Boolean.TRUE.equals(folded.get("ask_me"))));
        rec.template = new Template(rec.family, template);
        templates.put(id, rec.template);
        return reply(403, Map.of("error", "need_info", "ticket", mint(rec), "required_claims",
                List.of(Map.of("claim_type", CLAIM, "claim_token_format", List.of(FORMAT),
                        "friendly_name", "Terms for " + rec.account + ", held jointly", "terms_template", template))));
    }

    private ResponseEntity<Map<String, Object>> poll(Negotiation rec, JointMandate mandate) {
        for (JointMandate.Holder holder : mandate.holders()) {
            if (!"pending".equals(mandate.count(rec.effects).effect())) {
                break;
            }
            String owner = holder.owner();
            if (rec.effects.containsKey(owner)) {
                continue;
            }
            try {
                var response = ask(holder, "/joint/verdict", row("owner", owner, "account", rec.account,
                        "negotiation", rec.family, "resource_id", rec.resource, "contract", rec.digest,
                        "agreement", rec.agreement));
                if (response.status() >= 400 && response.status() < 500) {
                    rec.effects.put(owner, "refuse");
                    rec.reasons.put(owner, List.of("her authority refused to answer (" + response.status() + ")"));
                    continue;
                }
                if (!response.ok() || !(response.result().get("verdict") instanceof String token)) {
                    continue;
                }
                var verdict = JointVerdicts.verify(token, holder, peer::keys, now());
                String effect = text(verdict.get("effect"));
                if (!rec.family.equals(verdict.get("negotiation")) || !rec.resource.equals(verdict.get("resource_id"))
                        || !rec.digest.equals(verdict.get("contract")) || !List.of("allow", "refuse").contains(effect)
                        || "allow".equals(effect) && !mandate.digest().equals(verdict.get("mandate_s256"))) {
                    continue;
                }
                rec.effects.put(owner, effect);
                rec.proofs.put(owner, token);
                if (!list(verdict.get("because")).isEmpty()) {
                    rec.reasons.put(owner, list(verdict.get("because")));
                }
            } catch (RuntimeException unreachable) {
                log.event("verdict.unreachable", rec.family, "holder", owner);
            }
        }
        var count = mandate.count(rec.effects);
        return switch (count.effect()) {
            case "allow" -> reply(200, issue(rec, mandate, count));
            case "refuse" -> {
                negotiations.remove(rec.family);
                List<String> why = rec.reasons.values().stream().flatMap(List::stream)
                        .map(String::valueOf).toList();
                yield refused(403, "request_denied", why.isEmpty()
                        ? "the holders of this account did not agree" : String.join("; ", why));
            }
            default -> reply(403, Map.of("error", "request_submitted", "ticket", mint(rec), "interval", pollInterval));
        };
    }

    private Map<String, Object> issue(Negotiation rec, JointMandate mandate, JointMandate.Count count) {
        String jti = "rpt_" + uuid();
        long now = now();
        long offered = number(rec.template.wire.get("expires_in"), 900);
        long agreed = number(rec.contract.get("expires_in"), offered);
        long exp = now + Math.min(offered, agreed > 0 ? agreed : offered);
        List<String> proofs = new ArrayList<>();
        String heaviest = null;
        for (var entry : rec.proofs.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
            if (!"allow".equals(rec.effects.get(entry.getKey()))) {
                continue;
            }
            proofs.add(entry.getValue());
            var said = CompactJws.parse(entry.getValue()).claims();
            exp = Math.min(exp, number(said.get("exp"), exp));
            Integer candidate = Consequence.rank(said.get("consequence"));
            if (candidate != null && (heaviest == null || candidate > Consequence.rank(heaviest))) {
                heaviest = Consequence.normalise(said.get("consequence"));
            }
        }
        List<?> offeredScopes = list(rec.template.wire.get("scope"));
        List<?> agreedScopes = list(rec.contract.get("scope"));
        List<?> scopes = agreedScopes.isEmpty() ? offeredScopes
                : agreedScopes.stream().filter(offeredScopes::contains).toList();
        String handle = Jwks.thumbprint(rec.signer);
        Map<String, Object> claims = row("iss", issuer, "sub", handle, "client_id", handle,
                "owner", rec.account, "aud", audience, "jti", jti, "iat", now, "family", rec.family,
                "exp", exp, "cnf", Map.of("jwk", rec.signer), "permissions", List.of(Map.of(
                        "resource_id", rec.resource, "resource_scopes", scopes, "exp", exp)),
                "contract", rec.digest, "joint", Map.of("account", rec.account, "mandate",
                        Map.of("holders", mandate.wire().get("holders"), "rule", mandate.rule(),
                               "resources", mandate.resources()),
                        "verdicts", proofs, "tally", count.wire()));
        if (heaviest != null) {
            claims.put("consequence", heaviest);
        }
        Map<String, Object> operation = object(rec.contract.get("operation"));
        if (!operation.isEmpty()) {
            claims.put("single_use", true);
            claims.put("operation", Map.of("tool", operation.get("tool"), "params_s256",
                    S256.of(PyJson.compactSortedUnicode(operation.getOrDefault("params", Map.of())))));
        }
        String token = sign("at+jwt", claims);
        grants.put(jti, new Grant(claims));
        negotiations.remove(rec.family);
        return Map.of("access_token", token, "token_type", "PoP", "expires_in", exp - now);
    }

    @PostMapping(value = "/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    Map<String, Object> introspect(HttpServletRequest request, @RequestParam String token,
                                   @RequestParam(defaultValue = "false") boolean consume) {
        resourceAuth(request);
        Grant grant;
        try {
            grant = read(token);
        } catch (IllegalArgumentException invalid) {
            return Map.of("active", false, "error", invalid.getMessage());
        }
        synchronized (grant) {
            if (grant.spent) {
                return Map.of("active", false, "error", "already_consumed");
            }
            if (consume && Boolean.TRUE.equals(grant.claims.get("single_use"))) {
                grant.spent = true;
            }
            Map<String, Object> result = new LinkedHashMap<>(grant.claims);
            result.put("active", true);
            return result;
        }
    }

    @PostMapping(value = "/consume", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    Map<String, Object> consume(HttpServletRequest request, @RequestParam String token) {
        resourceAuth(request);
        Grant grant;
        try {
            grant = read(token);
        } catch (IllegalArgumentException invalid) {
            return Map.of("consumed", false, "error", invalid.getMessage());
        }
        synchronized (grant) {
            if (grant.spent) {
                return Map.of("consumed", false, "error", "already_consumed");
            }
            if (!Boolean.TRUE.equals(grant.claims.get("single_use"))) {
                return Map.of("consumed", false, "error", "not_single_use");
            }
            grant.spent = true;
            return Map.of("consumed", true);
        }
    }

    @PostMapping("/rs/register")
    Map<String, Object> register(HttpServletRequest request) {
        resourceAuth(request);
        return Map.of("status", "active");
    }

    @PostMapping("/audit/access")
    Map<String, Object> report(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        resourceAuth(request);
        log.event("access.reported", text(body.get("family")), "tool", body.get("tool"));
        return Map.of("recorded", true);
    }

    private Grant read(String token) {
        Map<String, Object> claims;
        try {
            var parsed = CompactJws.verify(token, key.getPublic());
            claims = parsed.claims();
            if (!issuer.equals(claims.get("iss")) || !audience.equals(claims.get("aud"))
                    || !"at+jwt".equals(parsed.header().get("typ"))) {
                throw new IllegalArgumentException("wrong issuer or audience");
            }
        } catch (RuntimeException invalid) {
            throw new IllegalArgumentException("invalid_signature");
        }
        if (number(claims.get("exp"), 0) <= now()) {
            throw new IllegalArgumentException("expired");
        }
        Grant grant = grants.get(text(claims.get("jti")));
        if (grant == null) {
            throw new IllegalArgumentException("unknown_token");
        }
        return grant;
    }

    private void resourceAuth(HttpServletRequest request) {
        String auth = request.getHeader("authorization");
        if (auth == null || !auth.startsWith("Bearer ") || !same(secret, auth.substring(7))) {
            throw error(HttpStatus.UNAUTHORIZED, "invalid_client");
        }
    }

    private String mint(Negotiation rec) {
        String ticket = random(24);
        tickets.put(ticket, new Ticket(rec.family, now() + ticketTtl));
        return ticket;
    }

    private void sweep() {
        long now = now();
        tickets.values().removeIf(ticket -> ticket.expires() < now);
        var live = tickets.values().stream().map(Ticket::family).collect(java.util.stream.Collectors.toSet());
        negotiations.values().removeIf(rec -> rec.touched < now - ticketTtl && !live.contains(rec.family));
        templates.values().removeIf(template -> !template.signed && !negotiations.containsKey(template.family));
        grants.values().removeIf(grant -> number(grant.claims.get("exp"), 0) < now);
    }

    private JointPeer.Reply ask(JointMandate.Holder holder, String path, Map<String, Object> fields) {
        var claims = new LinkedHashMap<>(fields);
        long now = now();
        claims.putAll(Map.of("iss", issuer, "iat", now, "exp", now + requestTtl));
        return peer.request("POST", holder.issuer() + path, Map.of("request", sign("u4a-tally-req+jwt", claims)));
    }

    private String sign(String type, Map<String, Object> claims) {
        return CompactJws.sign(Map.of("typ", type, "kid", kid), claims, key.getPrivate());
    }

    private static ResponseEntity<Map<String, Object>> refused(int status, String error, String why) {
        return reply(status, why == null ? Map.of("error", error)
                : Map.of("error", error, "error_description", why));
    }

    private static ResponseEntity<Map<String, Object>> reply(int status, Map<String, Object> body) {
        return ResponseEntity.status(status).body(body);
    }

    private static ResponseStatusException error(HttpStatus status, String detail) {
        return new ResponseStatusException(status, detail);
    }

    private static boolean same(String expected, String sent) {
        return sent != null && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                sent.getBytes(StandardCharsets.UTF_8));
    }

    private static long now() { return Instant.now().getEpochSecond(); }
    private static String uuid() { return UUID.randomUUID().toString().replace("-", "").substring(0, 12); }
    private static String env(String name, String fallback) { return System.getenv().getOrDefault(name, fallback); }
    private static String text(Object o) { return o instanceof String s ? s : ""; }
    private static long number(Object o, long fallback) { return o instanceof Number n ? n.longValue() : fallback; }
    private static List<?> list(Object o) { return o instanceof List<?> l ? l : List.of(); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object o) {
        return o instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }

    private static Map<String, Object> row(Object... fields) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < fields.length; i += 2) {
            out.put((String) fields[i], fields[i + 1]);
        }
        return out;
    }

    private static String random(int length) {
        byte[] value = new byte[length];
        RANDOM.nextBytes(value);
        return Jwks.b64url(value);
    }
}
