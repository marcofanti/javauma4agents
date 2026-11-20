package io.uma4agents.common;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** The electorate and resources the holders consented to count together. */
public record JointMandate(List<String> resources, List<JointMandate.Holder> holders,
                           String kind, long threshold, long totalWeight) {
    private static final Comparator<String> CODEPOINTS = (a, b) ->
            Arrays.compare(a.codePoints().toArray(), b.codePoints().toArray());

    public record Holder(String owner, String issuer, long weight) {
        public Map<String, Object> wire() {
            return Map.of("owner", owner, "issuer", issuer, "weight", weight);
        }
    }

    public static JointMandate parse(Object value, long floor) {
        if (!(value instanceof Map<?, ?> doc)) {
            throw new IllegalArgumentException("a mandate is a JSON object");
        }
        Object resource = doc.get("resources");
        List<?> names = resource instanceof String one ? List.of(one) : list(resource);
        if (names.isEmpty() || names.stream().anyMatch(name -> !(name instanceof String s)
                || PyStr.strip(s).isEmpty())) {
            throw new IllegalArgumentException("resources must name at least one id or pattern — a "
                    + "mandate over nothing governs nothing, and the holders would be agreeing "
                    + "to a document with no subject");
        }
        List<String> resources = names.stream().map(name -> PyStr.strip((String) name)).toList();
        List<?> candidates = list(doc.get("holders"));
        if (candidates.size() < 2) {
            throw new IllegalArgumentException("a mandate needs at least two holders — one holder "
                    + "is ownership, and it already has a mechanism");
        }
        List<Holder> holders = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        long total = 0;
        for (Object candidate : candidates) {
            if (!(candidate instanceof Map<?, ?> h)) {
                throw new IllegalArgumentException("each holder is an object");
            }
            String owner = PyStr.strip(text(h.get("owner")));
            if (owner.isEmpty()) {
                throw new IllegalArgumentException("a holder needs an owner id");
            }
            if (!seen.add(owner)) {
                throw new IllegalArgumentException(PyRepr.of(owner)
                        + " appears twice — a holder counted twice is a holder "
                        + "who outvotes the others by being listed again");
            }
            String issuer = PyStr.strip(text(h.get("issuer"))).replaceFirst("/+$", "");
            if (!https(issuer)) {
                throw new IllegalArgumentException("holder " + PyRepr.of(owner)
                        + " needs an https issuer: her verdicts are verified "
                        + "against the keys it publishes, and a plaintext origin "
                        + "has nothing to verify against");
            }
            long weight = h.containsKey("weight") ? integer(h.get("weight")) : 1;
            if (weight < 1) {
                throw new IllegalArgumentException(
                        "holder " + PyRepr.of(owner) + " needs an integer weight of 1 or more");
            }
            holders.add(new Holder(owner, issuer, weight));
            total = Math.addExact(total, weight);
        }
        Object candidate = doc.get("rule");
        if (doc.containsKey("rule") && !(candidate instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("rule must be an object");
        }
        Map<?, ?> rule = object(candidate);
        String kind = text(rule.get("kind"));
        if (kind.isEmpty()) {
            kind = "all";
        }
        long threshold = switch (kind) {
            case "all" -> total;
            case "any" -> holders.stream().mapToLong(Holder::weight).min().orElseThrow();
            case "threshold" -> integer(rule.get("threshold"));
            default -> throw new IllegalArgumentException(
                    "rule.kind must be one of ['all', 'any', 'threshold'], got " + PyRepr.of(kind));
        };
        if (threshold < 1 || threshold > total) {
            throw new IllegalArgumentException("rule.threshold must be between 1 and " + total
                    + ", the total weight of the holders");
        }
        if (floor > 0) {
            int persons = 0;
            long weight = 0;
            for (Holder h : holders.stream().sorted(
                    Comparator.comparingLong(Holder::weight).reversed()).toList()) {
                weight += h.weight;
                persons++;
                if (weight >= threshold) {
                    break;
                }
            }
            if (persons < floor) {
                throw new IllegalArgumentException("this resource requires at least " + floor
                        + " holders to agree to release it, and under this mandate " + persons
                        + " could. That floor is not the holders' to lower.");
            }
        }
        return new JointMandate(resources, List.copyOf(holders), kind, threshold, total);
    }

    public Map<String, Object> wire() {
        return Map.of("resources", resources, "holders", holders.stream().map(Holder::wire).toList(),
                "rule", rule(), "total_weight", totalWeight);
    }

    public Map<String, Object> rule() {
        return Map.of("kind", kind, "threshold", threshold);
    }

    public String digest() {
        return S256.of(PyJson.compactSortedUnicode(Map.of(
                "holders", holders.stream().sorted(Comparator.comparing(Holder::owner, CODEPOINTS))
                        .map(Holder::wire).toList(),
                "resources", resources.stream().sorted(CODEPOINTS).toList(),
                "rule", rule())));
    }

    public boolean governs(String resource) {
        return OrganizationPatterns.matches(resource, resources);
    }

    public Holder holder(String owner) {
        return holders.stream().filter(h -> h.owner.equals(owner)).findFirst().orElse(null);
    }

    public record Count(String effect, long allowed, long refused, long threshold, long totalWeight,
                        List<String> outstanding, String kind) {
        public Map<String, Object> wire() {
            return Map.of("effect", effect, "for", allowed, "against", refused,
                    "threshold", threshold, "total_weight", totalWeight,
                    "outstanding", outstanding, "rule", kind);
        }
    }

    public Count count(Map<String, String> verdicts) {
        long allowed = 0;
        long refused = 0;
        long pending = 0;
        List<String> outstanding = new ArrayList<>();
        for (Holder h : holders) {
            String effect = verdicts.get(h.owner);
            if ("allow".equals(effect)) {
                allowed += h.weight;
            } else if ("refuse".equals(effect)) {
                refused += h.weight;
            } else if (effect == null) {
                pending += h.weight;
                outstanding.add(h.owner);
            }
        }
        String effect = allowed >= threshold ? "allow"
                : allowed + pending < threshold ? "refuse" : "pending";
        outstanding.sort(CODEPOINTS);
        return new Count(effect, allowed, refused, threshold, totalWeight, outstanding, kind);
    }

    public List<String> changesTo(JointMandate published) {
        var descriptions = new ArrayList<String>();
        var added = published.holders.stream().map(Holder::owner).filter(owner -> holder(owner) == null)
                .sorted(CODEPOINTS).toList();
        var removed = holders.stream().map(Holder::owner).filter(owner -> published.holder(owner) == null)
                .sorted(CODEPOINTS).toList();
        if (!added.isEmpty()) {
            descriptions.add(String.join(", ", added) + " would join the holders of this account");
        }
        if (!removed.isEmpty()) {
            descriptions.add(String.join(", ", removed) + " would no longer be a holder");
        }
        for (Holder after : published.holders.stream().sorted(
                Comparator.comparing(Holder::owner, CODEPOINTS)).toList()) {
            Holder before = holder(after.owner);
            if (before == null) {
                continue;
            }
            if (!before.issuer.equals(after.issuer)) {
                descriptions.add(after.owner + "'s answers would come from " + after.issuer
                        + " rather than " + before.issuer);
            }
            if (before.weight != after.weight) {
                descriptions.add(after.owner + " would carry a weight of " + after.weight
                        + " rather than " + before.weight);
            }
        }
        if (threshold != published.threshold) {
            descriptions.add("it would take " + published.threshold + " of the holders' weight "
                    + "to release this rather than " + threshold);
        }
        if (!resources.stream().sorted(CODEPOINTS).toList()
                .equals(published.resources.stream().sorted(CODEPOINTS).toList())) {
            descriptions.add("the resources it covers would change");
        }
        if (!kind.equals(published.kind) && descriptions.isEmpty()) {
            descriptions.add("the rule for counting holders would change");
        }
        return List.copyOf(descriptions);
    }

    public List<String> describe() {
        String names = String.join(", ", holders.stream().map(Holder::owner).toList());
        String rule = switch (kind) {
            case "all" -> "Every holder has to allow a request before it is granted. Any one "
                    + "of you can stop it.";
            case "any" -> "Any one holder can release it alone. You are trusting each other's "
                    + "judgement, not only your own.";
            default -> "It takes " + threshold + " of " + totalWeight + " to release it"
                    + (holders.stream().anyMatch(h -> h.weight != 1)
                    ? ", and the holders do not carry equal weight." : ".");
        };
        return List.of("Held jointly by " + names + ", over " + String.join(", ", resources) + ".",
                rule, "The terms an agent must accept are every holder's terms at once: the "
                        + "shortest expiry any of you set, only the scopes all of you offer, "
                        + "and every prohibition any of you wrote.",
                "No holder can see another's terms over anything else, or act for her anywhere but here.");
    }

    public static Map<String, Object> fold(List<Map<String, Object>> quotes, List<String> resources) {
        if (quotes.isEmpty()) {
            throw new IllegalArgumentException("nothing to fold");
        }
        var first = quotes.getFirst();
        Map<String, Object> result = new LinkedHashMap<>(first);
        Map<String, Object> terms = new LinkedHashMap<>(object(first.get("terms")));
        result.put("terms", terms);
        for (int i = 1; i < quotes.size(); i++) {
            Map<String, Object> other = quotes.get(i);
            Map<String, Object> offered = object(other.get("terms"));
            var envelope = new LinkedHashMap<String, Object>();
            envelope.put("claims", resources);
            envelope.put("max_expires_in", offered.get("expires_in"));
            envelope.put("allowed_scopes", offered.get("scope"));
            envelope.put("require_prohibited", list(offered.get("prohibited")));
            envelope.put("always_ask", Boolean.TRUE.equals(other.get("ask_me")) ? resources : List.of());
            Map<String, Object> narrowed = OrganizationEnvelope.clamp(result, envelope).patch();
            terms.putAll(object(narrowed.get("terms")));
            if (Boolean.TRUE.equals(narrowed.get("ask_me"))) {
                result.put("ask_me", true);
            }
        }
        return result;
    }

    private static boolean https(String issuer) {
        try {
            URI url = URI.create(issuer);
            return "https".equals(url.getScheme()) && url.getHost() != null
                    && url.getUserInfo() == null && url.getQuery() == null && url.getFragment() == null;
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static long integer(Object candidate) {
        if (candidate instanceof Integer || candidate instanceof Long
                || candidate instanceof Short || candidate instanceof Byte) {
            return ((Number) candidate).longValue();
        }
        if (candidate instanceof java.math.BigInteger big && big.bitLength() <= 63) {
            return big.longValue();
        }
        return -1;
    }

    private static String text(Object value) {
        return value instanceof String s ? s : "";
    }

    private static List<?> list(Object value) {
        return value instanceof List<?> l ? l : List.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        return value instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }
}
