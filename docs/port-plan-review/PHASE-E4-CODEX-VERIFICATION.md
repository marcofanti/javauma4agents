# Independent Phase E4 controls

The reference is `77649287dc883b75ef563c59f96de8613ecf10d0`.
The unchanged XAA checker (blob `3c582334f2e757ee3b81c108961a1554d7932ad9`)
passed 30/30. The full upstream `smoke-test` also passed. It checked the
advertised ID-JAG format, separate Alice and Carol resource authorities,
both portals, and the enforcement and observability probes.

The fresh Python project published only the loopback edge port for the
host-side smoke probes. The upstream target ran unchanged with the Make
`CURL` setting redirected to that port. The project was then stopped.
[Reference output](phase-e4-evidence/codex-python-controls.txt).


## Java Cross App Access

The unchanged checker passed 30/30 on the Java stack. It proved directory
separation, workforce enrolment, discovery-driven exchange, enterprise scope
restriction, the charter's independent first-party rule, one-time assertion
use, Carol's audience boundary and the absence of the identity beat on Alice's
own account. Full smoke also passed, including ID-JAG publication at the AS,
the broker and workforce endpoints, and Carol's separate metadata and portal.

The broker accepts an ID token issued to the authenticating application and
looks up the exact application, audience and resource edge before asserting
an operation. It keeps those lab edges in memory and reloads the configured
seeds after restart, as upstream does. The owner AS checks the provider's
published signing keys and applies identity only inside the organization's
effective resource envelope. Java requires an expiry and checks a resource
claim when the provider supplies one. The member's charter remains subject
to explicit acceptance, and authority administrators and workforce employees
use different Keycloak realms.

Full Maven verification with PostgreSQL passed 262 tests. An earlier run
exposed a Phase C test race: it used independent counters to pick a replica
and pick the revoker, so some schedules never called revoke. The corrected test
elects exactly one revoker from replica B and checks all 16 issuance attempts
from replica A. Production store code did not change in this correction.

[Java XAA and smoke output](phase-e4-evidence/codex-java-focused.txt).

## Final sign-off

The rebuilt Java stack passed all 25 live gates from a clean reset.
That includes the 122 real-store cases, the 37 joint cases, the 30 XAA
cases and full smoke. Maven with PostgreSQL required passed all 262 tests.

[Final clean aggregate](phase-e4-evidence/codex-java-final-aggregate.txt).
[Full Java and PostgreSQL results](phase-e4-evidence/codex-java-maven.txt).
