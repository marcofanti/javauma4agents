package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/** The owner marker belongs to the wire ticket. The store indexes its opaque suffix. */
final class PermissionTickets {
    private PermissionTickets() {}

    static String mint(OwnerStore store, String owner, Map<String, Object> negotiation) {
        long ttl = "awaiting-owner".equals(negotiation.get("state"))
                ? AsConfig.PENDING_TTL : AsConfig.TICKET_TTL;
        negotiation.put("owner", owner);
        String prefix = Base64.getUrlEncoder().withoutPadding().encodeToString(ownerBytes(owner));
        return prefix + "~" + store.mintTicket(negotiation, ttl);
    }

    static String forOwner(String ticket, String owner) {
        if (ticket == null || ticket.isEmpty()) {
            return null;
        }
        int delimiter = ticket.indexOf('~');
        if (delimiter < 0) {
            return ticket; // Unmarked tickets already stored by an older deployment.
        }
        try {
            byte[] marker = Base64.getUrlDecoder().decode(ticket.substring(0, delimiter));
            return Arrays.equals(marker, ownerBytes(owner))
                    ? ticket.substring(delimiter + 1) : null;
        } catch (IllegalArgumentException invalidMarker) {
            return null;
        }
    }

    private static byte[] ownerBytes(String owner) {
        return owner.getBytes(StandardCharsets.UTF_8);
    }
}
