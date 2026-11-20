package io.uma4agents.organization;

import static io.uma4agents.organization.OrganizationCharter.object;
import static io.uma4agents.organization.OrganizationCharter.strings;
import static io.uma4agents.organization.OrganizationCharter.text;
import static io.uma4agents.organization.OrganizationMembership.number;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** The published charter translated into the disclosure to which the member agrees. */
final class CharterDisclosure {
    private CharterDisclosure() {}

    static List<String> summary(Map<String, Object> charter, Map<String, Object> role) {
        Map<String, Object> envelope = object(charter.get("envelope"));
        Map<String, Object> conditions = object(charter.get("conditions"));
        Map<String, Object> glass = object(charter.get("break_glass"));
        String grants = joined(role, "grants");
        String roleName = text(role.get("name"));
        var out = new ArrayList<>(List.of(
                "Shares " + (grants.isEmpty() ? "nothing" : grants) + " with you"
                        + (roleName.isEmpty() ? "." : ", as " + roleName + "."),
                switch (text(role.get("delegation"))) {
                    case "first-party-only" -> "Only agents you operate yourself may act on them. "
                            + "Somebody else's agent may not, whatever your own terms say.";
                    case "any-agent" -> "Any agent may act on them, if your own terms allow it.";
                    default -> "No agent may act on them on your behalf — only you.";
                },
                "Governs " + joined(charter, "claims") + " — your own accounts are outside this entirely.",
                "No grant over its resources may last longer than " + duration(envelope.get("max_expires_in"))
                        + ", whatever your own terms say."));
        if (envelope.get("allowed_scopes") instanceof List<?> scopes) {
            out.add(scopes.isEmpty() ? "No access at all may be granted while this is in force."
                    : "Only these may ever be granted: " + joined(envelope, "allowed_scopes") + ".");
        }
        String prohibited = joined(envelope, "require_prohibited");
        if (!prohibited.isEmpty()) {
            out.add("Your terms over its resources will always forbid: " + prohibited + ".");
        }
        Map<String, Object> clearance = new TreeMap<>(object(envelope.get("require_clearance")));
        if (!clearance.isEmpty()) {
            List<String> claims = clearance.entrySet().stream().map(entry -> {
                List<?> accepted = (List<?>) entry.getValue();
                return entry.getKey() + " (" + (accepted.isEmpty() ? "nothing accepted"
                        : String.join(" or ", accepted.stream().map(CharterDisclosure::spelled).toList())) + ")";
            }).toList();
            out.add("Its resources may only be reached while this organization can attest that "
                    + "you hold: " + String.join(", ", claims)
                    + " — it says this about you; you do not assert it yourself.");
        }
        String alwaysAsk = joined(envelope, "always_ask");
        if (!alwaysAsk.isEmpty()) {
            out.add("You will be asked every time for: " + alwaysAsk
                    + " — even if your own terms would have granted automatically.");
        }
        floor(out, conditions, "min_binding", "the request is bound to a key the authority verified");
        floor(out, conditions, "min_provenance", "the agent's credential traces to an issuer");
        floor(out, conditions, "min_accountability", "someone named is standing behind the agent");
        if (Boolean.TRUE.equals(conditions.get("require_reason"))) {
            out.add("An agent that does not say what it wants the access for is refused.");
        }
        if (Boolean.TRUE.equals(conditions.get("require_mission"))) {
            out.add("An agent that cites no mandate for its errand is refused.");
        }
        if (!text(charter.get("rego")).isEmpty()) {
            out.add("The organization applies operating rules of its own, evaluated by its policy "
                    + "engine — things like a close period or trading hours, which change without "
                    + "this agreement changing. They can only make a request harder, never easier, "
                    + "and whenever one of them stops you it is named in your own record.");
        }
        if (Boolean.TRUE.equals(glass.get("enabled"))) {
            out.add("Break-glass: the organization can reach " + joined(glass, "resources")
                    + " for up to " + duration(glass.get("max_expires_in")) + " without your approval, "
                    + "and every time it does you are told immediately and it is written into your own record.");
        } else {
            out.add("The organization cannot reach your resources without going through your policy "
                    + "like anyone else.");
        }
        return out;
    }

    static Map<String, Object> powers(Map<String, Object> charter, Map<String, Object> role) {
        Map<String, Object> envelope = object(charter.get("envelope"));
        Map<String, Object> glass = object(charter.get("break_glass"));
        String claims = joined(charter, "claims");
        String grants = joined(role, "grants");
        String roleName = text(role.get("name"));
        Map<String, String> delegation = switch (text(role.get("delegation"))) {
            case "first-party-only" -> power("Agents you operate yourself may act on them",
                    "An agent whose operator you claimed, and whose key that operator published, "
                            + "may be granted access under your terms. Somebody else's agent may not "
                            + "— however much you trust it, and whatever your own terms say.");
            case "any-agent" -> power("Any agent may act on them, if your terms allow it",
                    "Including agents other people operate. Your terms still decide what they may "
                            + "do, and this charter still caps it.");
            default -> power("No agent may act on them — only you", "You can reach the firm's book "
                    + "yourself. Nothing you delegate to an agent reaches it.");
        };
        var gets = List.of(power("Access to " + (grants.isEmpty() ? "nothing yet" : grants),
                "As " + (roleName.isEmpty() ? "a member" : roleName) + ". These are the "
                        + "organization's resources, shared with you — they appear in your own "
                        + "authorization server, and you write the terms agents must accept to touch them."),
                delegation);
        var can = new ArrayList<>(List.of(
                power("Set a ceiling on the terms you write over " + claims,
                        "No grant over them may last longer than " + duration(envelope.get("max_expires_in"))
                                + ", and prohibitions this charter requires are added to your terms "
                                + "whether you wrote them or not."),
                power("See the agents that touch its resources, and shut them out",
                        "An administrator can stop an agent reaching the firm's book without asking you. "
                                + "It does not end your relationship with that agent: whatever it "
                                + "does with your own accounts carries on untouched."),
                power("See requests waiting on you about its resources, and answer them",
                        "Approve or deny, in your place. Only requests about the organization's "
                                + "resources — it cannot see, or answer, a request about your own accounts."),
                power("Refuse a request your own terms would have allowed",
                        "Every request over its resources is judged by this organization's policy as "
                                + "well as yours. Either of you can stop it; neither can widen the other."),
                power("Change what you may reach, or end your membership",
                        "Your role here is theirs to set. Ending it takes back the access it gave you; "
                                + "what their ceiling narrowed in your own terms stays narrowed.")));
        var cannot = new ArrayList<>(List.of(
                power("Touch anything of yours", "This charter reaches " + claims
                        + " and nothing else. Your own accounts, the terms you write over them, "
                        + "and the agents that use them are outside it entirely — an administrator "
                        + "cannot see them, cannot answer for them, and cannot revoke them."),
                power("Read your policy", "Not even for its own resources. What crosses to this "
                        + "organization is that its ceiling was applied and which of its own fields "
                        + "narrowed you — never what you wrote."),
                power("Make your terms wider", "Nothing in this charter can lengthen an expiry, add a "
                        + "scope or remove a prohibition. It can only narrow."),
                power("Act as you", "Everything an administrator does is written into your record "
                        + "under their name, not yours, and you are told as it happens.")));
        if (Boolean.TRUE.equals(glass.get("enabled"))) {
            can.add(power("Break glass — reach its own resources without your approval",
                    "On " + joined(glass, "resources") + ", for up to " + duration(glass.get("max_expires_in"))
                            + " at a time, without going through your authorization server at all. "
                            + "You cannot stop it, and it cannot be done quietly: you are told the moment "
                            + "it is opened, before any data moves, and every use is written into your own record."));
        } else {
            cannot.add(1, power("Reach its resources without going through your policy",
                    "This charter has no break-glass clause. An agent acting for this organization "
                            + "negotiates with your authorization server like anyone else's."));
        }
        return Map.of("gets", gets, "can", can, "cannot", cannot);
    }

    private static Map<String, String> power(String what, String detail) {
        return Map.of("what", what, "detail", detail);
    }

    private static void floor(List<String> lines, Map<String, Object> conditions,
                              String field, String sentence) {
        long value = number(conditions.get(field), 0);
        if (value > 0) {
            lines.add("Requests are refused unless " + sentence + " (level " + value + ").");
        }
    }

    private static String joined(Map<String, Object> source, String field) {
        return String.join(", ", strings(source.get(field), field));
    }

    private static String duration(Object seconds) {
        long value = number(seconds, 0);
        if (value == 0) {
            return "—";
        }
        long[] sizes = {86_400, 3_600, 60};
        String[] units = {"day", "hour", "minute"};
        for (int i = 0; i < sizes.length; i++) {
            if (value >= sizes[i] && value % sizes[i] == 0) {
                long count = value / sizes[i];
                return count + " " + units[i] + (count == 1 ? "" : "s");
            }
        }
        return value + " seconds";
    }

    private static String spelled(Object value) {
        return value instanceof Boolean b ? (b ? "True" : "False") : String.valueOf(value);
    }
}
