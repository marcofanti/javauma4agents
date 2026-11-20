package io.uma4agents.authserver.store;

import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * One owner's state. Methods are intents, not accessors: every method that guards a
 * single-use resource makes its decision and its write as one step and reports whether
 * the caller won, so the check-then-act race cannot move into the caller.
 *
 * <p>Records are JSON-shaped maps. Every read returns a copy the caller owns; a change
 * persists only through a write method. Both implementations behave that way, so code
 * that works on one cannot rely on in-place mutation the other does not have.
 *
 * <p>Two behaviours are required and easy to "fix" by accident. Consuming a ticket
 * removes only the index entry: the negotiation stays addressable by family, so her
 * portal can still see and decide a pending request between one ticket being spent and
 * its rotation being issued. And the family is the stable identity; the ticket is only a
 * credential for it.
 */
public interface OwnerStore {

    /**
     * Gives a new owner her starting tiers and resource servers, once per owner rather
     * than once per empty table: what she removed or changed stays as she left it.
     */
    void seed();

    // --- negotiations and tickets -------------------------------------------

    /**
     * Persists the negotiation and indexes a fresh ticket to it. Sets the record's
     * {@code expires} from {@code ttlSeconds}. A decision already stored, and who made
     * it, survive this write even when {@code rec} is a copy read before she answered.
     *
     * @return the new ticket
     */
    String mintTicket(Map<String, Object> rec, double ttlSeconds);

    /** Burns the ticket and returns its live negotiation, or null; one atomic step. */
    Map<String, Object> consumeTicket(String ticket);

    /** The live negotiation a ticket names, without spending the ticket; or null. */
    Map<String, Object> peekTicket(String ticket);

    Map<String, Object> negotiation(String family);

    /** Stores a negotiation, creating it when unseen. A stored decision is write-once. */
    void saveNegotiation(Map<String, Object> rec);

    /** Binds a joint negotiation family to its first signed contract. */
    boolean beginJointNegotiation(Map<String, Object> rec);

    void putMandate(String account, Map<String, Object> record);

    Map<String, Map<String, Object>> mandates();

    boolean clearMandate(String account);

    /** Reports a newly observed change while preserving a concurrent re-enrolment. */
    boolean markMandateMoved(String account, Map<String, Object> expected, List<String> changes);

    /** Drops a finished negotiation and every ticket still indexed to it. */
    void closeNegotiation(String family);

    /** Sweeps negotiations whose window closed with nobody returning; returns how many. */
    int reapExpired();

    /** Every negotiation awaiting her, undecided. */
    List<Map<String, Object>> pendingNegotiations();

    /**
     * Records a decision and who made it in one step. False when there is no undecided
     * negotiation awaiting her under that family, so a second tap decides nothing.
     */
    boolean decide(String family, String decision, Map<String, Object> decidedBy);

    // --- RPTs ---------------------------------------------------------------

    void recordRpt(String jti, String family, String handle, Map<String, Object> operation,
                   String tier);

    Map<String, Object> rpt(String jti);

    /** Burns a single-use RPT: its family, or null when unknown or already spent. */
    String consumeRpt(String jti);

    // --- standing relationships ---------------------------------------------

    Map<String, Object> connection(String handle);

    /** Writes a connection record, replacing it wholly; callers carry forward the rest. */
    void putConnection(Map<String, Object> conn);

    /** Every connection, most recently first seen first. */
    List<Map<String, Object>> connections();

    /**
     * Writes a connection she has just admitted, only if nothing was revoked since she was
     * asked: the stored revocation count (zero when there is no record) must still be
     * {@code expectedRevocations}. Serialized with {@link #revokeConnection} on the
     * connection itself, so a revocation committed first is never overwritten.
     *
     * @return whether the connection was written
     */
    boolean admitConnection(Map<String, Object> conn, int expectedRevocations);

    /**
     * Records a grant under a connection, only if that connection is active and its
     * revocation count is still {@code expectedRevocations}. Serialized with
     * {@link #revokeConnection}: a grant recorded first is burned by the revocation, and a
     * revocation committed first refuses the grant, so no live grant outlives one.
     *
     * @return whether the grant was recorded
     */
    boolean recordRptIfConnected(String jti, String family, String handle,
                                 Map<String, Object> operation, String tier,
                                 int expectedRevocations);

    /** Records last access. Telemetry: an unknown handle is ignored. */
    void touchConnection(String handle, String when);

    /**
     * Deactivates the connection, bumps its revocation count, and burns every live RPT
     * issued under it, in one step.
     *
     * @return how many RPTs were burned, or null when the connection is unknown
     */
    Integer revokeConnection(String handle);

    /**
     * Remembers that this connection has been granted at this tier. A policy input
     * ({@code standing.first_at_tier}), so it appends-if-absent in one step: concurrent
     * grants cannot lose each other's write. An unknown handle is ignored.
     */
    void noteTierGrant(String handle, String tierId);

    /**
     * Remembers that she personally approved something at this tier, apart from what the
     * server granted: only this one may relax a rule. Append-if-absent in one step.
     */
    void noteTierApproval(String handle, String tierId);

    /**
     * Every tier she personally approved for {@code root} and its live sub-agents, as one
     * set. Revoked members are excluded.
     */
    List<String> lineageApprovals(String root);

    /** How many live sub-agents this connection has introduced. */
    int countChildren(String handle);

    // --- operators she has shut out, and ones she says are hers ------------

    /** Origins whose agents she will not deal with, each with when she said so. */
    Map<String, Map<String, Object>> blockedOperators();

    /** Shuts out an operator. Idempotent: the first block's time is kept. */
    void blockOperator(String origin, String when);

    /** False when it was not blocked. */
    boolean unblockOperator(String origin);

    /** Origins she has claimed as hers, each with when she said so. */
    Map<String, Map<String, Object>> ownedOperators();

    /** Says an origin is hers. Idempotent: the first claim's time is kept. */
    void claimOperator(String origin, String when);

    /** False when it was not claimed. */
    boolean disclaimOperator(String origin);

    // --- resource servers ---------------------------------------------------

    Map<String, Map<String, Object>> resourceServers();

    Map<String, Object> resourceServer(String clientId);

    void putResourceServer(String clientId, Map<String, Object> rs);

    /** Moves an unknown or revoked origin to pending. True when the owner should be notified. */
    boolean pendResourceServer(String clientId, Map<String, Object> registration);

    /** Transitions only a pending registration to active. */
    boolean approveResourceServer(String clientId, String consented);

    /**
     * Sets only the stored secret, in one step, and returns the record as it now stands;
     * null when there is none. Every other field, status above all, is whatever the latest
     * write left: a revocation that lands at the same moment stays a revocation.
     */
    Map<String, Object> updateResourceServerSecret(String clientId, String secret);

    void touchPat(String clientId, String when);

    /** False when the client is unknown. */
    boolean revokeResourceServer(String clientId);

    Map<String, Object> organization();

    void putOrganization(Map<String, Object> membership);

    /** Updates only the enrollment represented by the observed credential. */
    boolean updateOrganization(String token, Map<String, Object> fields);

    /** Clears only the enrollment represented by the observed credential. */
    boolean clearOrganization(String token);

    /** Changes one organization-only block. A null timestamp removes the block. */
    boolean setOrganizationBlock(String token, String group, String key, String timestamp);

    // --- owner-visible documents --------------------------------------------

    /**
     * Appends one decision record. {@code handle} is a column, not an entry key, so an
     * entry cannot shadow it; it is null where there is no agent to attribute.
     */
    void ledgerAdd(String kind, String family, String ts, Map<String, Object> entry,
                   String handle);

    /** The whole record, or one agent's part of it when {@code handle} is set; oldest first. */
    List<Map<String, Object>> ledger(String handle);

    /** {@code {handle, tier}} of the grant a negotiation issued, after it is closed; or null. */
    Map<String, Object> grantForFamily(String family);

    /**
     * What this agent has done lately, from her ledger at or after {@code since} (a
     * fixed-width UTC stamp): {@code {"denials": n, "tiers": [sorted], "calls": n}}. Not an
     * indivisible step: it only ever tightens a requirement, so a stale read behaves like a
     * request that arrived a moment earlier.
     */
    Map<String, Object> trajectory(String handle, String since);

    /** Archives a terms version. Write-once per template id. */
    void publishTerms(Map<String, Object> doc);

    Map<String, Object> termsDoc(String templateId);

    /** Every published version, ordered by template id. */
    List<Map<String, Object>> termsDocs();

    // --- her policy ---------------------------------------------------------

    /** Her tiers, ordered by tier id. */
    Map<String, Map<String, Object>> tiers();

    /**
     * Applies a pure edit to one tier atomically, so two edits at once give two version
     * bumps in order rather than one lost edit.
     *
     * @throws java.util.NoSuchElementException for an unknown tier
     */
    Map<String, Object> updateTier(String tierId, UnaryOperator<Map<String, Object>> edit);

    /**
     * Adds a tier she wrote. The uniqueness test and the write are one step, so two replicas
     * cannot both believe they created it.
     *
     * @throws IllegalStateException when the id is taken
     */
    Map<String, Object> createTier(String tierId, Map<String, Object> tier);

    /** Removes a tier; false when it was not there. Its resources become ungoverned. */
    boolean deleteTier(String tierId);

    // --- single-use values ---------------------------------------------------

    /**
     * True the first time {@code key} is spent, false every time after until
     * {@code expiresEpochSeconds}; one atomic step across replicas. A value that may be
     * acted on once must be acted on once by the deployment, not once per process.
     */
    boolean spendOnce(String key, double expiresEpochSeconds);

    // --- fan-out to her surface ---------------------------------------------

    /** Publishes an event to this owner's subscribers on every replica. */
    void notify(Map<String, Object> payload);

    /** This owner's event stream: every event any replica publishes for her, and no other's. */
    Subscription subscribe();
}
