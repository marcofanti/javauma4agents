package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.Clearance;
import io.uma4agents.common.OrganizationEnvelope;
import io.uma4agents.common.PyRepr;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Her tier policy, kept in her store: a small, legible document, not a policy language.
 * Each tier names the resources it covers, the terms the AS dictates, whether granting asks
 * her, and her rules about the requests that reach it. What stays here is what is policy
 * rather than state: the default she starts from, how an owner edit is applied, and how
 * deep a queue of strangers she will hold. Ported from the pinned {@code policy.py}.
 */
@Component
public class PolicyService {

    /** The level an agent cannot reach on its own say-so: its operator published its key. */
    public static final int ATTRIBUTABLE_AT = 2;

    /** Prohibitions the enforcement point refuses, gated on the tier switch that turns it on. */
    private static final Map<String, String[]> ENFORCED_PROHIBITIONS = Map.of(
            "orders-beyond-approved-parameters", new String[] {"per_operation", "operation-binding"},
            "discretionary-reuse-of-authority", new String[] {"per_operation", "single-use"});

    private final OwnerStore store;
    private final AsConfig config;

    public PolicyService(OwnerStore store, AsConfig config) {
        this.store = store;
        this.config = config;
    }

    /** The tiers a new owner starts with, with her default rules; seeded once into her store. */
    public static Map<String, Map<String, Object>> defaults() {
        return defaults("alice");
    }

    public static Map<String, Map<String, Object>> defaults(String owner) {
        String vault = owner + "-vault/";
        String template = owner + "/advisor-";
        Map<String, Map<String, Object>> tiers = new LinkedHashMap<>();
        tiers.put("tier1", tier(
                "Holdings summary",
                List.of(vault + "get_positions"),
                false,
                List.of(rule(List.of("assurance.accountability_below:1"), Rules.ASK)),
                terms(template + "tier1/v2",
                        "Suitability review for advisory onboarding",
                        List.of("positions:read"), 172800,
                        List.of("retention-after-review", "marketing", "model-training"),
                        null, false)));
        tiers.put("tier2", tier(
                "Transaction history and cost basis",
                List.of(vault + "get_transactions"),
                false,
                List.of(rule(List.of("standing.first_at_tier"), Rules.ASK)),
                terms(template + "tier2/v2",
                        "Portfolio analysis for the current advisory engagement",
                        List.of("transactions:read"), 86400,
                        List.of("client-benchmarking", "sharing-outside-engagement-team",
                                "retention-after-engagement"),
                        Map.of("accounts", List.of("brokerage-main")), false)));
        tiers.put("tier3", tier(
                "Trade execution",
                List.of(vault + "execute_trade"),
                true,
                List.of(),
                terms(template + "tier3/v2",
                        "Execution of one client-approved order",
                        List.of("trades:execute"), 900,
                        List.of("orders-beyond-approved-parameters",
                                "discretionary-reuse-of-authority"),
                        null, true)));
        return tiers;
    }

    private static Map<String, Object> rule(List<String> when, String then) {
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("when", new ArrayList<>(when));
        rule.put("then", then);
        return rule;
    }

    private static Map<String, Object> tier(String name, List<String> resources, boolean askMe,
                                            List<Map<String, Object>> rules,
                                            Map<String, Object> terms) {
        Map<String, Object> tier = new LinkedHashMap<>();
        tier.put("name", name);
        tier.put("resources", new ArrayList<>(resources));
        tier.put("ask_me", askMe);
        tier.put("rules", new ArrayList<>(rules));
        tier.put("terms", terms);
        return tier;
    }

    private static Map<String, Object> terms(String templateId, String purpose,
                                             List<String> scope, int expiresIn,
                                             List<String> prohibited,
                                             Map<String, Object> constraints,
                                             boolean perOperation) {
        Map<String, Object> terms = new LinkedHashMap<>();
        terms.put("template_id", templateId);
        terms.put("purpose", purpose);
        terms.put("scope", new ArrayList<>(scope));
        terms.put("expires_in", expiresIn);
        terms.put("prohibited", new ArrayList<>(prohibited));
        if (constraints != null) {
            terms.put("constraints", constraints);
        }
        if (perOperation) {
            terms.put("per_operation", true);
        }
        return terms;
    }

    /**
     * Which of this tier's prohibitions are refused at the door, and by what. Derived on
     * every read: the answer follows from the tier's own switches.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> enforcedProhibitions(Map<String, Object> tier) {
        Map<String, Object> terms = tier.get("terms") instanceof Map<?, ?> t
                ? (Map<String, Object>) t : Map.of();
        Map<String, Object> out = new LinkedHashMap<>();
        if (terms.get("prohibited") instanceof List<?> prohibited) {
            for (Object name : prohibited) {
                String[] gate = ENFORCED_PROHIBITIONS.get(String.valueOf(name));
                if (gate != null && Py.truthy(terms.get(gate[0]))) {
                    out.put(String.valueOf(name), gate[1]);
                }
            }
        }
        return out;
    }

    /** Her tiers, in tier-id order. */
    public Map<String, Map<String, Object>> tiers() {
        return store.tiers();
    }

    /** Returns {tierId, tier} for the resource, or null when no tier governs it. */
    public Map.Entry<String, Map<String, Object>> tierForResource(String resourceId) {
        return tierForResource(store.tiers(), resourceId);
    }

    static Map.Entry<String, Map<String, Object>> tierForResource(
            Map<String, Map<String, Object>> tiers, String resourceId) {
        for (Map.Entry<String, Map<String, Object>> e : tiers.entrySet()) {
            if (e.getValue().get("resources") instanceof List<?> list
                    && list.contains(resourceId)) {
                return Map.entry(e.getKey(), e.getValue());
            }
        }
        return null;
    }

    // --- her attention ------------------------------------------------------

    /** The queue an assessed agent waits in. Better evidence buys less friction, not access. */
    public static String pendLane(Map<String, Object> axes) {
        Object accountability = axes == null ? null : axes.get("accountability");
        int level = accountability instanceof Number n ? n.intValue() : 0;
        return level >= ATTRIBUTABLE_AT ? "attributable" : "unattributable";
    }

    public int pendBudget(String lane) {
        return "attributable".equals(lane) ? config.pendBudgetAttributed : config.pendBudget;
    }

    // --- owner edits --------------------------------------------------------

    /**
     * An owner edit, applied by the store in one step so two edits give two version bumps.
     *
     * @throws java.util.NoSuchElementException for an unknown tier
     * @throws IllegalArgumentException for rules or a requirement that will not evaluate
     */
    public Map<String, Object> updateTier(String tierId, Map<String, Object> patch) {
        return updateTier(tierId, patch, Map.of());
    }

    Map<String, Object> updateTier(String tierId, Map<String, Object> patch,
                                   Map<String, Object> envelope) {
        return store.updateTier(tierId, tier -> applyPatch(tier, patch, envelope));
    }

    /**
     * Owner edits: terms fields, the ask-me switch, her rules and a clearance requirement.
     * Resources are fixed by registration. Every edit bumps the template version so a
     * signed agreement is tied to the terms in force when it was signed. Pure: it edits the
     * copy it is given.
     */
    static Map<String, Object> applyPatch(Map<String, Object> tier, Map<String, Object> patch) {
        return applyPatch(tier, patch, Map.of());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> applyPatch(Map<String, Object> tier, Map<String, Object> patch,
                                                 Map<String, Object> envelope) {
        applyValues(tier, patch);
        clamp(tier, envelope);
        Map<String, Object> terms = (Map<String, Object>) tier.get("terms");
        String templateId = (String) terms.get("template_id");
        int split = templateId.lastIndexOf("/v");
        String base = templateId.substring(0, split);
        int version = Integer.parseInt(templateId.substring(split + 2)) + 1;
        terms.put("template_id", base + "/v" + version);
        return tier;
    }

    static void clamp(Map<String, Object> tier, Map<String, Object> envelope) {
        applyValues(tier, OrganizationEnvelope.clamp(tier, envelope).patch());
    }

    @SuppressWarnings("unchecked")
    private static void applyValues(Map<String, Object> tier, Map<String, Object> patch) {
        if (patch.containsKey("ask_me")) {
            tier.put("ask_me", Py.truthy(patch.get("ask_me")));
        }
        if (patch.containsKey("rules")) {
            Rules.validate(patch.get("rules"));
            tier.put("rules", patch.get("rules"));
        }
        if (patch.containsKey("clearance")) {
            tier.put("clearance", Clearance.validateRequirement(patch.get("clearance"), "clearance"));
        }
        Map<String, Object> terms = (Map<String, Object>) tier.get("terms");
        if (patch.get("terms") instanceof Map<?, ?> termsPatch) {
            for (String field : List.of("purpose", "expires_in", "prohibited", "scope",
                    "constraints")) {
                if (termsPatch.containsKey(field)) {
                    terms.put(field, termsPatch.get(field));
                }
            }
        }
    }

    /**
     * A tier she is adding, or IllegalArgumentException saying why not: a slug id that is
     * new; resources registered and ungoverned (a resource belongs to one tier); terms with
     * a purpose and a lifetime; rules that may only relax on her own decisions.
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> newTier(String tierId, Map<String, Object> spec,
                                       Map<String, Map<String, Object>> existing,
                                       Set<String> registered, Set<String> jointlyHeld,
                                       String owner) {
        if (tierId.isEmpty() || !tierId.codePoints().allMatch(
                cp -> isAlnum(cp) || cp == '-' || cp == '_')) {
            throw new IllegalArgumentException(
                    "a tier id may contain letters, digits, - and _ only");
        }
        if (existing.containsKey(tierId)) {
            throw new IllegalArgumentException(
                    "there is already a tier called " + PyRepr.of(tierId));
        }
        List<Object> resources = listOf(spec.get("resources"));
        List<String> mixed = new ArrayList<>();
        boolean other = false;
        for (Object rid : resources) {
            if (jointlyHeld.contains(rid)) {
                mixed.add(String.valueOf(rid));
            } else {
                other = true;
            }
        }
        if (!mixed.isEmpty() && other) {
            throw new IllegalArgumentException(String.join(", ",
                    new java.util.TreeSet<>(mixed)) + " is held jointly, and terms over it "
                    + "cannot share a tier with anything else — they are half somebody "
                    + "else's, and an edit here would change what his agents are held to as "
                    + "well. Give it a tier of its own.");
        }
        Map<Object, String> governed = new LinkedHashMap<>();
        existing.forEach((tid, t) -> listOf(t.get("resources")).forEach(
                r -> governed.put(r, tid)));
        for (Object rid : resources) {
            if (!registered.contains(rid)) {
                throw new IllegalArgumentException(
                        PyRepr.of(rid) + " is not a resource this authority protects");
            }
            if (governed.containsKey(rid)) {
                throw new IllegalArgumentException(PyRepr.of(rid) + " is already governed by "
                        + PyRepr.of(governed.get(rid)) + " — a resource belongs to one tier, "
                        + "or which terms apply would depend on the order they happen to be "
                        + "stored in");
            }
        }
        Map<String, Object> terms = spec.get("terms") instanceof Map<?, ?> t
                ? new LinkedHashMap<>((Map<String, Object>) t) : new LinkedHashMap<>();
        for (String field : List.of("purpose", "expires_in")) {
            if (!Py.truthy(terms.get(field))) {
                throw new IllegalArgumentException("terms need a " + field);
            }
        }
        Object rules = Py.truthy(spec.get("rules")) ? spec.get("rules") : List.of();
        Rules.validate(rules);
        Map<String, Object> outTerms = new LinkedHashMap<>();
        outTerms.put("template_id", owner + "/" + tierId + "/v1");
        outTerms.put("purpose", terms.get("purpose"));
        outTerms.put("scope", listOf(terms.get("scope")));
        outTerms.put("expires_in", Py.toInt(terms.get("expires_in")));
        outTerms.put("prohibited", listOf(terms.get("prohibited")));
        if (Py.truthy(terms.get("per_operation"))) {
            outTerms.put("per_operation", true);
        }
        if (terms.get("constraints") instanceof Map<?, ?> constraints) {
            outTerms.put("constraints", new LinkedHashMap<>(constraints));
        }
        Map<String, Object> tier = new LinkedHashMap<>();
        tier.put("name", Py.truthy(spec.get("name")) ? spec.get("name") : tierId);
        tier.put("resources", resources);
        tier.put("ask_me", Py.truthy(spec.get("ask_me")));
        tier.put("rules", rules);
        tier.put("clearance", Clearance.validateRequirement(spec.get("clearance"), "clearance"));
        tier.put("terms", outTerms);
        return tier;
    }

    /** {@code list(x or [])} for a JSON value: a string is its characters, as in Python. */
    private static List<Object> listOf(Object value) {
        if (!Py.truthy(value)) {
            return new ArrayList<>();
        }
        if (value instanceof List<?> list) {
            return new ArrayList<>(list);
        }
        if (value instanceof Map<?, ?> map) {
            return new ArrayList<>(map.keySet());
        }
        if (value instanceof String text) {
            List<Object> out = new ArrayList<>();
            text.codePoints().forEach(cp -> out.add(new String(Character.toChars(cp))));
            return out;
        }
        throw new IllegalArgumentException("expected a list, got " + PyRepr.of(value));
    }

    /** CPython {@code str.isalnum} for one code point. */
    private static boolean isAlnum(int cp) {
        int type = Character.getType(cp);
        return Character.isLetter(cp) || type == Character.DECIMAL_DIGIT_NUMBER
                || type == Character.LETTER_NUMBER || type == Character.OTHER_NUMBER;
    }

}
