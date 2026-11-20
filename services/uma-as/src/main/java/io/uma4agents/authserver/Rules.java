package io.uma4agents.authserver;

import io.uma4agents.common.Consequence;
import io.uma4agents.common.PyRepr;
import io.uma4agents.common.PyStr;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Her rules: policy that faces the agent without naming one. Conjunction inside a rule,
 * disjunction across rules, nothing else. Restrictions beat relaxations, and only a
 * decision she made may relax. Pure functions of dict-shaped facts, ported from the pinned
 * {@code services/uma-as/policy.py}, so the same JSON produces the same answer.
 */
public final class Rules {

    public static final String AUTO = "auto";
    public static final String ASK = "ask";
    public static final String REFUSE = "refuse";
    private static final Map<String, Integer> RANK = Map.of(AUTO, 0, ASK, 1, REFUSE, 2);

    /** Facts traceable to a decision she personally made: the only ones that may relax. */
    public static final Set<String> RELAXING = Set.of(
            "standing.approved_at_tier", "standing.never_revoked", "standing.age_above",
            "standing.first_party");

    public static final Set<String> OBSERVED = Set.of(
            "standing.none", "standing.first_at_tier", "standing.revoked_before",
            "standing.age_below", "standing.denials_above", "standing.tiers_above",
            "standing.calls_above", "standing.introduced", "standing.lineage_new_at_tier");

    /** Evidence the requesting side supplied, or facts about what it asked for. */
    public static final Set<String> ASSURANCE = Set.of(
            "assurance.binding_below", "assurance.provenance_below",
            "assurance.accountability_below", "request.max_expiry", "request.reason_absent",
            "request.mission_absent", "request.consequence_at_or_above",
            "request.consequence_unknown");

    private static final Set<String> DURATION_ARGS =
            Set.of("standing.age_above", "standing.age_below");
    private static final Set<String> LEVEL_ARGS = Set.of("assurance.binding_below",
            "assurance.provenance_below", "assurance.accountability_below");
    private static final Set<String> COUNT_ARGS = Set.of("standing.denials_above",
            "standing.tiers_above", "standing.calls_above");
    private static final Set<String> CLASS_ARGS = Set.of("request.consequence_at_or_above");

    private static final String UNEVALUABLE = "a rule that could not be evaluated";

    private Rules() {}

    static boolean isStanding(String name) {
        return RELAXING.contains(name) || OBSERVED.contains(name);
    }

    static boolean isCondition(String name) {
        return isStanding(name) || ASSURANCE.contains(name);
    }

    private static boolean takesArg(String name) {
        return DURATION_ARGS.contains(name) || LEVEL_ARGS.contains(name)
                || COUNT_ARGS.contains(name) || CLASS_ARGS.contains(name);
    }

    // --- vocabulary ---------------------------------------------------------

    private static final List<String[]> VOCABULARY = List.of(
            new String[] {"assurance.binding_below:1", null,
                "the request is not bound to a key this authority verified"},
            new String[] {"assurance.provenance_below:1", null,
                "the agent's credential cannot be traced to an issuer"},
            new String[] {"assurance.accountability_below:1", null,
                "nobody named and reachable is standing behind the agent"},
            new String[] {"assurance.accountability_below:2", null,
                "the named operator has not published this agent's key"},
            new String[] {"request.max_expiry", null,
                "it asked for the longest access this tier allows"},
            new String[] {"request.reason_absent", null,
                "it did not say what it wants the access for"},
            new String[] {"request.mission_absent", null,
                "it cited no mandate for what it is doing"},
            new String[] {"request.consequence_at_or_above:compensatable", null,
                "undoing it would take a second action, or more"},
            new String[] {"request.consequence_at_or_above:forward_recoverable", null,
                "it cannot be undone, only recovered from"},
            new String[] {"request.consequence_at_or_above:irreversible", null,
                "it cannot be undone at all"},
            new String[] {"request.consequence_unknown", null,
                "nobody has said whether it can be undone"},
            new String[] {"standing.none", null,
                "I have no standing connection with this agent"},
            new String[] {"standing.first_at_tier", null,
                "it has never been granted at this tier before"},
            new String[] {"standing.revoked_before", null, "I have revoked this agent before"},
            new String[] {"standing.introduced", null, "it was introduced by another agent"},
            new String[] {"standing.lineage_new_at_tier", null,
                "I have approved nothing at this tier for this agent or the ones it works with"},
            new String[] {"standing.age_below", "duration",
                "I have known this agent for less than"},
            new String[] {"standing.first_party", null, "it is an agent I activated myself"},
            new String[] {"standing.never_revoked", null, "I have never revoked this agent"},
            new String[] {"standing.approved_at_tier", null,
                "I have personally approved something at this tier"},
            new String[] {"standing.age_above", "duration",
                "I have known this agent for more than"},
            new String[] {"standing.denials_above", "count",
                "I have recently denied this agent more times than"},
            new String[] {"standing.tiers_above", "count",
                "it has recently asked at more tiers than"},
            new String[] {"standing.calls_above", "count",
                "it has recently made more calls than"});

    /** The conditions an owner may write, and whether each may relax a requirement. */
    public static List<Map<String, Object>> vocabulary() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String[] entry : VOCABULARY) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("condition", entry[0]);
            row.put("takes", entry[1]);
            row.put("label", entry[2]);
            row.put("may_relax", RELAXING.contains(entry[0].split(":", 2)[0]));
            out.add(row);
        }
        return out;
    }

    // --- arguments ----------------------------------------------------------

    /** {@code 90d}, {@code 12h}, {@code 45m}, {@code 30s}, or plain seconds, as CPython reads them. */
    static BigInteger parseDuration(Object text) {
        String stripped = PyStr.strip(text == null ? "None" : String.valueOf(text));
        if (!stripped.isEmpty()) {
            int unit = switch (stripped.charAt(stripped.length() - 1)) {
                case 's' -> 1;
                case 'm' -> 60;
                case 'h' -> 3600;
                case 'd' -> 86400;
                default -> 0;
            };
            if (unit != 0) {
                double seconds = Py.toFloat(stripped.substring(0, stripped.length() - 1))
                        .doubleValue() * unit;
                if (Double.isNaN(seconds) || Double.isInfinite(seconds)) {
                    throw new IllegalArgumentException("cannot convert float to integer");
                }
                return new BigDecimal(seconds).toBigInteger();
            }
        }
        return Py.toInt(stripped);
    }

    private record Split(String name, String value) {}

    private static Split split(Object condition) {
        if (!(condition instanceof String text)) {
            throw new IllegalArgumentException("a condition must be a string");
        }
        int colon = text.indexOf(':');
        if (colon < 0) {
            return new Split(text, null);
        }
        String value = text.substring(colon + 1);
        return new Split(text.substring(0, colon), value.isEmpty() ? null : value);
    }

    private static String reprList(java.util.Collection<String> values) {
        List<String> parts = new ArrayList<>();
        for (String value : new TreeSet<>(values)) {
            parts.add(PyRepr.of(value));
        }
        return "[" + String.join(", ", parts) + "]";
    }

    // --- validation ---------------------------------------------------------

    /**
     * Refuses a rule set before it is stored, saying why: one that could widen access on
     * evidence the agent controls, or one that would not evaluate.
     *
     * @throws IllegalArgumentException with the pinned message
     */
    public static void validate(Object rules) {
        if (!(rules instanceof List<?> list)) {
            throw new IllegalArgumentException("rules must be a list");
        }
        for (Object rule : list) {
            if (!(rule instanceof Map<?, ?> r)) {
                throw new IllegalArgumentException("a rule must be an object of when and then");
            }
            Object then = r.get("then");
            if (!(then instanceof String t) || !RANK.containsKey(t)) {
                throw new IllegalArgumentException("rule `then` must be one of "
                        + reprList(RANK.keySet()) + ", got " + reprOf(then));
            }
            Object when = r.get("when");
            if (when instanceof String single) {
                when = List.of(single);
            }
            if (!(when instanceof List<?> conditions) || conditions.isEmpty()) {
                throw new IllegalArgumentException(
                        "rule `when` must be a non-empty condition or list");
            }
            for (Object condition : conditions) {
                validateCondition(condition, t);
            }
        }
    }

    private static String reprOf(Object value) {
        return value instanceof List<?> || value instanceof Map<?, ?>
                ? String.valueOf(value) : PyRepr.of(value);
    }

    private static void validateCondition(Object condition, String then) {
        Split s = split(condition);
        if (!isCondition(s.name())) {
            throw new IllegalArgumentException("unknown condition " + PyRepr.of(s.name()));
        }
        if (takesArg(s.name())) {
            if (s.value() == null) {
                throw new IllegalArgumentException(PyRepr.of(s.name()) + " needs an argument, as "
                        + s.name() + ":<value>");
            }
            checkArgument(s);
        } else if (s.value() != null) {
            throw new IllegalArgumentException(PyRepr.of(s.name()) + " takes no argument, got "
                    + PyRepr.of(s.value()));
        }
        if (AUTO.equals(then) && !RELAXING.contains(s.name())) {
            String why = !isStanding(s.name())
                    ? "assurance is supplied by the requesting side, and a signal the "
                            + "counterparty influences must never widen access"
                    : "it records what this server did, not what Alice decided; relaxing on "
                            + "it would let one automatic grant justify the next";
            throw new IllegalArgumentException(PyRepr.of(s.name())
                    + " cannot relax a requirement — " + why + ". Only "
                    + reprList(RELAXING) + " may lower one.");
        }
    }

    private static void checkArgument(Split s) {
        try {
            if (DURATION_ARGS.contains(s.name())) {
                parseDuration(s.value());
            } else if (CLASS_ARGS.contains(s.name())) {
                if (Consequence.normalise(s.value()) == null) {
                    throw new IllegalArgumentException("not a consequence class");
                }
            } else if (Py.toInt(s.value()).signum() < 0) {
                throw new IllegalArgumentException("negative");
            }
        } catch (IllegalArgumentException e) {
            String kind = DURATION_ARGS.contains(s.name()) ? "duration"
                    : COUNT_ARGS.contains(s.name()) ? "count"
                    : CLASS_ARGS.contains(s.name()) ? "consequence class" : "level";
            throw new IllegalArgumentException(PyRepr.of(s.name()) + " takes a " + kind
                    + ", got " + PyRepr.of(s.value()));
        }
    }

    // --- evaluation ---------------------------------------------------------

    /** What a request needs before it may be granted, and the conditions that decided it. */
    public record Outcome(String requirement, List<String> because) {}

    /**
     * Relaxations first, restrictions last and they win, so no combination of matched rules
     * is more permissive than the strictest thing that matched.
     */
    public static Outcome evaluate(Map<String, Object> tier, Map<String, Object> facts) {
        String baseline = Py.truthy(tier.get("ask_me")) ? ASK : AUTO;
        List<Object> rules = rulesOf(tier.get("rules"));
        String relaxed = baseline;
        List<String> reasons = List.of();
        for (Object rule : rules) {
            if (!AUTO.equals(effect(rule)) || RANK.get(AUTO) >= RANK.get(relaxed)) {
                continue;
            }
            Match m = ruleMatches(rule, facts);
            if (m.matched()) {
                relaxed = AUTO;
                reasons = m.when();
            }
        }
        String result = relaxed;
        for (Object rule : rules) {
            String then = effect(rule);
            if (RANK.get(then) <= RANK.get(result)) {
                continue;
            }
            Match m = ruleMatches(rule, facts);
            if (m.matched()) {
                result = then;
                reasons = m.when();
            }
        }
        return new Outcome(result, reasons);
    }

    /** {@code tier.get("rules") or []}, iterated as Python would iterate it. */
    private static List<Object> rulesOf(Object rules) {
        if (!Py.truthy(rules)) {
            return List.of();
        }
        if (rules instanceof List<?> list) {
            return new ArrayList<>(list);
        }
        if (rules instanceof Map<?, ?> map) {
            return new ArrayList<>(map.keySet());
        }
        if (rules instanceof String text) {
            List<Object> chars = new ArrayList<>();
            text.codePoints().forEach(cp -> chars.add(new String(Character.toChars(cp))));
            return chars;
        }
        return List.of();
    }

    /** A rule's effect; one this server does not recognise is put to her. */
    private static String effect(Object rule) {
        Object then = rule instanceof Map<?, ?> r ? r.get("then") : null;
        return then instanceof String t && RANK.containsKey(t) ? t : ASK;
    }

    private record Match(boolean matched, List<String> when) {}

    /**
     * Whether every condition holds. A rule that cannot be evaluated fails towards the
     * owner: an unusable restriction matches, an unusable relaxation does not.
     */
    private static Match ruleMatches(Object rule, Map<String, Object> facts) {
        try {
            if (!(rule instanceof Map<?, ?> r) || !r.containsKey("when")) {
                throw new IllegalArgumentException("malformed rule");
            }
            List<?> when = r.get("when") instanceof List<?> l ? l : List.of(nullSafe(r.get("when")));
            for (Object condition : when) {
                if (!matches(condition, facts)) {
                    return new Match(false, stringsOf(when));
                }
            }
            return new Match(true, stringsOf(when));
        } catch (RuntimeException e) {
            return new Match(!AUTO.equals(effect(rule)), List.of(UNEVALUABLE));
        }
    }

    private static Object nullSafe(Object value) {
        return value == null ? new Object() : value;
    }

    private static List<String> stringsOf(List<?> when) {
        List<String> out = new ArrayList<>();
        for (Object c : when) {
            out.add(String.valueOf(c));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static boolean matches(Object condition, Map<String, Object> facts) {
        Split s = split(condition);
        String name = s.name();
        Map<String, Object> standing = (Map<String, Object>) require(facts, "standing");
        Map<String, Object> assurance = (Map<String, Object>) require(facts, "assurance");
        Object tierId = facts.get("tier");
        Map<String, Object> request = facts.get("request") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : null;
        switch (name) {
            case "standing.none":
                return !Py.truthy(require(standing, "active"));
            case "standing.first_party":
                return Py.truthy(standing.get("first_party"));
            case "standing.first_at_tier":
                return Py.truthy(require(standing, "first_at_tier"));
            case "standing.introduced":
                return Py.truthy(standing.get("introduced"));
            case "standing.lineage_new_at_tier":
                return !standing.containsKey("lineage_new_at_tier")
                        || Py.truthy(standing.get("lineage_new_at_tier"));
            case "standing.approved_at_tier":
                return standing.get("approved_tiers") instanceof List<?> l && l.contains(tierId);
            case "standing.never_revoked":
                return Py.toInt(require(standing, "revocations")).signum() == 0;
            case "standing.revoked_before":
                return Py.toInt(require(standing, "revocations")).signum() > 0;
            case "standing.age_above", "standing.age_below":
                Object age = require(standing, "age_seconds");
                if (age == null) {
                    return "standing.age_below".equals(name);
                }
                int cmp = new BigDecimal(age.toString())
                        .compareTo(new BigDecimal(parseDuration(s.value())));
                return "standing.age_above".equals(name) ? cmp > 0 : cmp < 0;
            case "standing.denials_above":
                return Py.toInt(trajectory(standing).getOrDefault("denials", 0))
                        .compareTo(Py.toInt(s.value())) > 0;
            case "standing.tiers_above":
                Object tiers = trajectory(standing).getOrDefault("tiers", List.of());
                return BigInteger.valueOf(((List<?>) tiers).size())
                        .compareTo(Py.toInt(s.value())) > 0;
            case "standing.calls_above":
                return Py.toInt(trajectory(standing).getOrDefault("calls", 0))
                        .compareTo(Py.toInt(s.value())) > 0;
            default:
                break;
        }
        if (name.startsWith("assurance.")) {
            int end = name.length() - "_below".length();
            String axis = end > "assurance.".length()
                    ? name.substring("assurance.".length(), end) : "";
            return Py.toInt(assurance.getOrDefault(axis, 0)).compareTo(Py.toInt(s.value())) < 0;
        }
        if (request == null) {
            throw new IllegalArgumentException("no request facts");
        }
        return switch (name) {
            case "request.max_expiry" -> new BigDecimal(String.valueOf(require(request, "expires_in")))
                    .compareTo(new BigDecimal(String.valueOf(require(request, "max_expires_in"))))
                    >= 0;
            case "request.reason_absent" -> {
                Object reason = request.get("reason");
                if (!Py.truthy(reason)) {
                    yield true;
                }
                if (!(reason instanceof String text)) {
                    throw new IllegalArgumentException("reason is not text");
                }
                yield PyStr.strip(text).isEmpty();
            }
            case "request.mission_absent" -> !Py.truthy(request.get("mission"));
            case "request.consequence_at_or_above" ->
                    Consequence.atOrAbove(request.get("consequence"), s.value());
            case "request.consequence_unknown" ->
                    Consequence.normalise(request.get("consequence")) == null;
            default -> throw new IllegalArgumentException("unknown condition " + PyRepr.of(name));
        };
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> trajectory(Map<String, Object> standing) {
        return standing.get("trajectory") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : Map.of();
    }

    private static Object require(Map<String, Object> map, String key) {
        if (!map.containsKey(key)) {
            throw new IllegalArgumentException("missing fact " + key);
        }
        return map.get(key);
    }
}
