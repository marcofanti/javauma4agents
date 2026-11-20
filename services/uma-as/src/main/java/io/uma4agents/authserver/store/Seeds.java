package io.uma4agents.authserver.store;

import java.util.Map;
import java.util.function.Function;

/**
 * What a new owner starts with: her default tiers and the resource servers provisioned
 * alongside her authority. Applied once per owner by {@link OwnerStore#seed()}.
 *
 * @param tiers the default tiers for an owner, by tier id
 * @param resourceServers the provisioned resource servers for an owner, by client id
 */
public record Seeds(Function<String, Map<String, Map<String, Object>>> tiers,
                    Function<String, Map<String, Map<String, Object>>> resourceServers) {}
