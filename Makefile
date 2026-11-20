SHELL=/bin/bash -o pipefail

.PHONY: init dns-setup up down logs reset fetch-upstream

# Pinned upstream ref for the AAuth person server (built, not vendored)
PERSON_SERVER_REF = 18d9558
PAIOS_REF = b65d858f12c1da472176829af4b533a9e7c246e2

## fetch-upstream: clone the pinned AAuth person server into aauth/upstream/
fetch-upstream:
	@mkdir -p aauth/upstream
	@if [ ! -d aauth/upstream/aauth-person-server/.git ]; then \
		git clone https://github.com/christian-posta/aauth-person-server aauth/upstream/aauth-person-server; \
	fi
	@cd aauth/upstream/aauth-person-server && git fetch -q && git checkout -q $(PERSON_SERVER_REF)
	@echo "Upstream pinned: person-server@$(PERSON_SERVER_REF)"

## init: generate local CA, TLS certs, and signing keys; configure local DNS
init:
	mkdir -p ./certs

	# Edge server cert (envoy - external traffic on *.uma.lab)
	CAROOT=./certs mkcert \
		-cert-file=./certs/edge-server.pem \
		-key-file=./certs/edge-server-key.pem \
		localhost "*.uma.lab"

	# Internal server cert (services behind the edge)
	CAROOT=./certs mkcert \
		-cert-file=./certs/internal-server.pem \
		-key-file=./certs/internal-server-key.pem \
		"*.uma.lab" 127.0.0.1

	# Keycloak server cert (Alice's identity provider)
	CAROOT=./certs mkcert \
		-cert-file=./certs/keycloak-server.pem \
		-key-file=./certs/keycloak-server-key.pem \
		keycloak.uma.lab

	# Internal client cert for mTLS (edge -> internal services)
	CAROOT=./certs mkcert -client \
		-cert-file=./certs/internal-client.pem \
		-key-file=./certs/internal-client-key.pem \
		edge

	# uma-as signing key pair (RPT and intent-contract receipts)
	openssl genrsa -out ./certs/uma-as-signing-key.pem 2048
	openssl rsa -in ./certs/uma-as-signing-key.pem -pubout -out ./certs/uma-as-signing-pub.pem

	$(MAKE) owner-key
	$(MAKE) dns-setup

	@echo ""
	@echo "==> Init complete. Run: make up"
	@echo "==> Optional (browser trust for https://*.uma.lab): make trust-ca"

## owner-key: Alice's own device key. She makes it; only the public half reaches her
## authorization server (UMA_AS_OWNER_KEY), the second, independent way she reaches
## her own authority beside the portal's OIDC session. `make up` runs it first, so a
## Phase A checkout gets the key before Compose bind-mounts it. Never rotates; see
## scripts/owner-key.sh for what it refuses.
.PHONY: owner-key
owner-key:
	@scripts/owner-key.sh ./certs

## trust-ca: add the local CA to the system trust store (browser use; may prompt)
.PHONY: trust-ca
trust-ca:
	CAROOT=./certs mkcert -install

## dns-setup: point the OS resolver for uma.lab at the local DNS container
dns-setup:
	@case "$$(uname)" in \
		Darwin) \
			if [ -f /etc/resolver/uma.lab ]; then \
				echo "DNS already configured: /etc/resolver/uma.lab"; \
			else \
				echo "Configuring DNS resolver for uma.lab (requires sudo)..."; \
				sudo mkdir -p /etc/resolver && \
				echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/uma.lab > /dev/null && \
				echo "Created /etc/resolver/uma.lab"; \
			fi ;; \
		Linux) \
			if [ -f /etc/systemd/resolved.conf.d/uma.lab.conf ]; then \
				echo "DNS already configured: /etc/systemd/resolved.conf.d/uma.lab.conf"; \
			else \
				echo "Configuring DNS resolver for uma.lab (requires sudo)..."; \
				sudo mkdir -p /etc/systemd/resolved.conf.d && \
				printf "[Resolve]\nDNS=127.0.0.1\nDomains=~uma.lab\n" | \
					sudo tee /etc/systemd/resolved.conf.d/uma.lab.conf > /dev/null && \
				sudo systemctl restart systemd-resolved && \
				echo "Created /etc/systemd/resolved.conf.d/uma.lab.conf"; \
			fi ;; \
		*) \
			echo "Unsupported OS. Manually configure DNS for uma.lab to resolve via 127.0.0.1:53" ;; \
	esac

up: fetch-upstream owner-key
	docker compose up -d --build

down:
	docker compose down --timeout 2 --volumes --remove-orphans

logs:
	docker compose logs -f

## demo acts: walk the day headlessly (same code path as the agent-shim)
.PHONY: demo-tier1 demo-tier2 demo-tier3 demo-all
## first contact pends as a connection request on any tier (the day-1
## handshake), so every act accepts SIM=1 to simulate Alice's tap
demo-tier1:
	docker compose --profile demo run --rm demo-driver --act tier1 $(if $(SIM),--simulate-alice)
demo-tier2:
	docker compose --profile demo run --rm demo-driver --act tier2 $(if $(SIM),--simulate-alice)
## demo-tier3: pends until Alice approves in her portal (https://portal.uma.lab);
## add SIM=1 to simulate her tap for fully headless runs
demo-tier3:
	docker compose --profile demo run --rm demo-driver --act tier3 $(if $(SIM),--simulate-alice)
demo-all:
	docker compose --profile demo run --rm demo-driver --act $(or $(ACT),all) $(if $(filter 1 true yes,$(SIM)),--simulate-alice)

## demo-all-sim: the whole pinned day (tier1, tier2, tier3, first-party, revocation) with
## Alice's taps simulated: `make demo-all SIM=1`, as a live gate.
.PHONY: demo-all-sim
demo-all-sim:
	+@$(MAKE) --no-print-directory demo-all SIM=1

## audit: print Alice's activity ledger (promised / touched / personally approved)
# Logs in as Alice for real (direct-access grant at her IdP) — the owner API
# takes her OIDC token, not a static credential.
.PHONY: audit
audit:
	@docker compose exec -T uma-as sh -c '\
	TOK=$$(curl -s --cacert /certs/rootCA.pem \
		-d "grant_type=password&client_id=meridian-portal&username=alice&password=alice-demo" \
		https://keycloak.uma.lab/realms/alice/protocol/openid-connect/token \
		| sed -n "s/.*\"access_token\":\"\([^\"]*\)\".*/\1/p"); \
	curl -s -H "Authorization: Bearer $$TOK" http://localhost:9000/owner/ledger' \
	| python3 -m json.tool

## smoke-alice: the Phase A smoke profile — the pinned smoke probes that need only
## Alice's topology. The full upstream smoke-test also probes Carol's hosts and
## ID-JAG advertising, and becomes a gate in Phase E4.
# Uses curl --connect-to + --cacert so it works before make dns-setup / trust-ca, and
# against whichever host port the edge is published on (UMA4A_EDGE_PORT).
UMA4A_EDGE_PORT ?= 443
CURL = curl -sk --cacert ./certs/rootCA.pem \
	--connect-to alice-as.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to keycloak.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to gateway.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to portal.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to carol-portal.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to carol-as.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to northwind-xaa.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to northwind-idp.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to grafana.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to ps.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to agent.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT) \
	--connect-to alice-agent.uma.lab:443:127.0.0.1:$(UMA4A_EDGE_PORT)

.PHONY: smoke-alice smoke-test xaa-check
smoke-alice:
	@echo "==> uma-as discovery..."
	@$(CURL) https://alice-as.uma.lab/.well-known/uma4agents-configuration | grep -q token_endpoint \
		&& $(CURL) https://alice-as.uma.lab/.well-known/uma4agents-configuration | grep -q terms_endpoint \
		&& echo "  uma-as: OK" || { echo "  uma-as: FAIL"; exit 1; }
	@echo "==> ... at UMA 2.0's well-known path, naming the profile it implements..."
	@$(CURL) https://alice-as.uma.lab/.well-known/uma2-configuration \
		| grep -q '"uma_profiles_supported": *\[[^]]*https://u4a.ai/spec/core/1.0' \
		&& echo "  uma_profiles_supported: OK" || { echo "  uma_profiles_supported: FAIL"; exit 1; }
	@echo "==> ... and the grant types and endpoints this phase serves..."
	@$(CURL) https://alice-as.uma.lab/.well-known/uma2-configuration | grep -q 'client_credentials' \
		&& $(CURL) https://alice-as.uma.lab/.well-known/uma2-configuration | grep -q 'consume_endpoint' \
		&& $(CURL) https://alice-as.uma.lab/.well-known/uma2-configuration | grep -q 'owner_endpoint' \
		&& echo "  advertised formats: OK" || { echo "  advertised formats: FAIL"; exit 1; }
	@echo "==> ... and no push-registration endpoint, which this phase removed..."
	@! $(CURL) https://alice-as.uma.lab/.well-known/uma2-configuration | grep -q 'resource_registration_endpoint' \
		&& [ "$$($(CURL) -o /dev/null -w '%{http_code}' https://alice-as.uma.lab/rreg)" != 200 ] \
		&& echo "  no RReg: OK" || { echo "  no RReg: FAIL"; exit 1; }
	@echo "==> uma-as JWKS..."
	@$(CURL) https://alice-as.uma.lab/jwks | grep -q Ed25519 && echo "  jwks: OK" || { echo "  jwks: FAIL"; exit 1; }
	@echo "==> Keycloak alice realm..."
	@$(CURL) https://keycloak.uma.lab/realms/alice/.well-known/openid-configuration | grep -q issuer \
		&& echo "  keycloak: OK" || { echo "  keycloak: FAIL"; exit 1; }
	@echo "==> Protected Resource Metadata (RFC 9728) at the gateway..."
	@$(CURL) https://gateway.uma.lab/.well-known/oauth-protected-resource/mcp/alice \
		| grep -q '"authorization_servers":\["https://alice-as.uma.lab"\]' \
		&& echo "  resource metadata (alice): OK" || { echo "  resource metadata (alice): FAIL"; exit 1; }
	@echo "==> Gateway challenges an unauthorized tool call (expect 401 + UMA ticket)..."
	@RESP=$$($(CURL) -i https://gateway.uma.lab/mcp -X POST \
		-H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
		-d '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"get_positions","arguments":{}}}'); \
		echo "$$RESP" | grep -qi 'www-authenticate: UMA' && echo "$$RESP" | grep -q 'ticket=' \
		&& echo "  gateway challenge: OK" || { echo "  gateway challenge: FAIL"; exit 1; }; \
		echo "==> ext_authz denial body reaches the client verbatim..."; \
		echo "$$RESP" | grep -q 'uma_challenge' \
		&& echo "  ext_authz body passthrough: OK" || { echo "  ext_authz body passthrough: FAIL"; exit 1; }
	@echo "==> A truncated authorization body fails closed, by name..."
	@OUT=$$(docker compose exec -T uma-pep curl -s -w ' %{http_code}' -X POST \
		http://127.0.0.1:9002/check/mcp -H 'content-type: application/json' \
		-H 'x-envoy-auth-partial-body: true' \
		-d '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"exec'); \
		echo "$$OUT" | grep -q 'request_body_too_large' && echo "$$OUT" | grep -q ' 413$$' \
		&& echo "  truncated body: OK" || { echo "  truncated body: FAIL ($$OUT)"; exit 1; }
	@echo "==> Alice's portal..."
	@$(CURL) https://portal.uma.lab/health | grep -q ok && echo "  portal: OK" || { echo "  portal: FAIL"; exit 1; }
	@echo "==> Agent operator: CIMD document (self-referential client_id)..."
	@$(CURL) https://agent.uma.lab/agent.json | grep -q '"client_id": *"https://agent.uma.lab/agent.json"' \
		&& echo "  agent CIMD: OK" || { echo "  agent CIMD: FAIL"; exit 1; }
	@echo "==> Agent operator: Web Bot Auth key directory..."
	@$(CURL) -i https://agent.uma.lab/.well-known/http-message-signatures-directory \
		| grep -qi 'application/http-message-signatures-directory+json' \
		&& echo "  signatures directory: OK" || { echo "  signatures directory: FAIL"; exit 1; }
	@echo "==> Alice's own operator: the same service, her origin and name..."
	@$(CURL) https://alice-agent.uma.lab/agent.json \
		| grep -q '"client_id": *"https://alice-agent.uma.lab/agent.json"' \
		&& $(CURL) https://alice-agent.uma.lab/agent.json | grep -q "Alice's own agent" \
		&& echo "  alice operator CIMD: OK" || { echo "  alice operator CIMD: FAIL"; exit 1; }
	@echo "==> Person server discovery..."
	@$(CURL) https://ps.uma.lab/.well-known/aauth-person.json | grep -q token_endpoint \
		&& echo "  person-server: OK" || { echo "  person-server: FAIL"; exit 1; }
	@echo "==> Grafana..."
	@$(CURL) https://grafana.uma.lab/api/health | grep -q ok && echo "  grafana: OK" || { echo "  grafana: FAIL"; exit 1; }
	@echo "==> Loki has protocol events from this project's PEP..."
	@PEP=$$(docker compose ps --format '{{.Name}}' uma-pep); \
	[ -n "$$PEP" ] || { echo "  loki events: FAIL (no uma-pep container in this project)"; exit 1; }; \
	docker compose exec -T loki wget -qO- "http://localhost:3100/loki/api/v1/query_range?query=%7Bcontainer%3D%22$$PEP%22%2Cevent%3D%22challenge.issued%22%7D&limit=1" 2>/dev/null \
		| grep -q challenge.issued && echo "  loki events: OK ($$PEP)" || { echo "  loki events: FAIL (may need a challenge first + a few seconds)"; exit 1; }
	@echo "==> ... and an allowed call there carries the caller's W3C trace context..."
	@PEP=$$(docker compose ps --format '{{.Name}}' uma-pep); \
	docker compose exec -T loki wget -qO- "http://localhost:3100/loki/api/v1/query_range?query=%7Bcontainer%3D%22$$PEP%22%2Cevent%3D%22access.allowed%22%7D&limit=20" 2>/dev/null \
		| grep -q 'traceparent\\":\\"00-' && echo "  trace events: OK ($$PEP)" || { echo "  trace events: FAIL (needs an authorized call first)"; exit 1; }

## smoke-test: the full pinned smoke assertions, including Carol and ID-JAG discovery.
smoke-test: smoke-alice
	@python3 -c "import socket; socket.gethostbyname('gateway.uma.lab')" 2>/dev/null \
		&& echo "  DNS: OK" || echo "  DNS: not configured (smoke uses the isolated edge port)"
	@$(CURL) https://alice-as.uma.lab/.well-known/uma2-configuration \
		| grep -q 'urn:ietf:params:oauth:token-type:id-jag' \
		&& echo "  ID-JAG advertised: OK" || { echo "  ID-JAG advertised: FAIL"; exit 1; }
	@$(CURL) https://gateway.uma.lab/.well-known/oauth-protected-resource/mcp/carol \
		| grep -q '"authorization_servers":\["https://carol-as.uma.lab"\]' \
		&& echo "  resource metadata (carol): OK" || { echo "  resource metadata (carol): FAIL"; exit 1; }
	@$(CURL) https://carol-portal.uma.lab/health | grep -q ok \
		&& echo "  carol portal: OK" || { echo "  carol portal: FAIL"; exit 1; }
	@$(CURL) https://northwind-xaa.uma.lab/.well-known/openid-configuration \
		| grep -q 'id_jag_identity_provider' \
		&& echo "  XAA broker discovery: OK" || { echo "  XAA broker discovery: FAIL"; exit 1; }
	@$(CURL) https://northwind-idp.uma.lab/realms/employees/.well-known/openid-configuration \
		| grep -q issuer && echo "  Northwind workforce realm: OK" \
		|| { echo "  Northwind workforce realm: FAIL"; exit 1; }

## reset: rewind demo state without tearing the stack down
# Grant-layer state (tickets, contracts, ledger) is in memory by default
# (UMA_AS_STORE=memory); restarting the services rewinds the story. A durable store is
# not rewound by a restart: reset it by replacing its database, as store-test and
# rotation-check each do.
reset:
	docker compose restart uma-as carol-as org-authority joint-tally xaa-broker uma-pep agentgateway
	@printf "Waiting for enforcement to come back"; \
	for i in $$(seq 1 30); do \
		docker compose exec -T uma-pep curl -sf http://localhost:9002/health >/dev/null 2>&1 && break; \
		printf "."; sleep 1; \
	done; echo
	@echo "Demo state rewound."

## shim-test: verify the agent-shim under a scripted MCP client (both approval paths)
.PHONY: shim-test
shim-test:
	docker compose --profile test run --rm shim-test

## vendor-verify: the vendored upstream clients still match their pinned blobs
.PHONY: vendor-verify
vendor-verify:
	@scripts/verify-vendored.sh

## check-unit: everything that needs no running stack (CI runs this)
## check-live: the pinned upstream gates against the Compose stack (phase sign-off)
## check-all: both halves, unit first
.PHONY: check-unit check-live check-all
check-unit: vendor-verify
	mvn -B -ntp verify
# Recipes, not prerequisites: under `make -jN` prerequisites run concurrently, and the
# live gates share one stack whose vault, policy and owner state they change.
check-all:
	+$(MAKE) --no-print-directory check-unit
	+$(MAKE) --no-print-directory check-live

## embedded-check: the grant against a resource that protects itself
## (ENFORCEMENT_MODE=embedded), no gateway in the path. Restores gateway mode and
## verifies the restoration; see scripts/embedded-check.sh for the exit status.
.PHONY: embedded-check
embedded-check:
	@scripts/embedded-check.sh

## ts-agent-check: the pinned TypeScript agent, sharing no code with the others
.PHONY: ts-agent-check
ts-agent-check:
	docker compose --profile test run --rm ts-agent-check

## demo-acts-a: the Phase A driver acts, pseudonymous, with Alice's taps simulated
.PHONY: demo-acts-a
demo-acts-a:
	@for act in tier1 tier2 tier3 revocation; do \
		echo "==> demo act $$act"; \
		docker compose --profile demo run --rm demo-driver --act $$act \
			--pseudonymous --simulate-alice || exit 1; \
	done

## decline-check: supplemental decline assertion outside the vendored TypeScript client
.PHONY: decline-check
decline-check:
	docker compose --profile test run --rm decline-check

## shim-spike: Phase A spike evidence for the shim's stdio and HTTP boundaries
.PHONY: shim-spike
shim-spike:
	docker compose --profile test run --rm shim-spike

## fixture: the grant with nothing standing behind it (compose.fixture.yml) — no
## identity provider, database or gateway. Alice signs her owner-API requests with
## her own key; the vault serves its own TLS. Runs the pinned fixture_check.py
## against the Java uma-as and vault, in its own Compose project.
FIXTURE_PROJECT ?= javauma4agents-fixture
FIXTURE = docker compose -p $(FIXTURE_PROJECT) -f compose.fixture.yml
.PHONY: fixture fixture-down
fixture:
	$(FIXTURE) up -d --build --wait owner-keygen uma-as alice-vault-mcp
	$(FIXTURE) --profile check run --rm fixture-check

fixture-down:
	$(FIXTURE) down --timeout 2 --volumes --remove-orphans

## flow-check: four agents, four identity regimes, one unchanged owner — the pinned
## check that agent identity never reaches her decision, and that a withdrawn agent
## gets no fresh token from the person server.
.PHONY: flow-check
flow-check:
	docker compose --profile test run --rm flow-check

## demo-acts-b: the pinned driver's acts as an identified agent (enrolled with the
## person server, with operator CIMD and Web Bot Auth), Alice's taps simulated
.PHONY: demo-acts-b
demo-acts-b:
	@for act in tier1 tier2 tier3 revocation; do \
		echo "==> demo act $$act (identified)"; \
		docker compose --profile demo run --rm demo-driver --act $$act \
			--simulate-alice || exit 1; \
	done

## token-test: the focused AAuth agent-token, owner-authentication and handle tests
.PHONY: token-test
token-test:
	mvn -B -ntp -q -pl lib/uma4a-common,services/uma-as -am verify -Dsurefire.failIfNoSpecifiedTests=false \
		-Dtest='AgentTokensTest,OwnerAuthTest,ConnectionHandleTest'

## store-test: the store properties on memory and on real Postgres 17, including two
## store instances (two replicas) on one database, restart and reseed, stale-schema
## refusal, listener reconnection and transaction failure. Postgres is required: an
## absent database fails the run. Uses UMA_AS_TEST_DSN when set (it must name a
## disposable database, since every test class drops the store's tables); otherwise it
## starts a throwaway postgres:17-alpine on an ephemeral loopback port and removes it.
STORE_TEST_PG ?= javauma4agents-store-test-pg
STORE_TESTS = MemoryStoreTest,JdbcStoreTest,JdbcReplicaTest,SqlTransactionTest,PgDsnTest
.PHONY: store-test
store-test:
	@scripts/store-test.sh '$(STORE_TEST_PG)' '$(STORE_TESTS)'

## rotation-check: the authority rotates its signing key under live grants (the pinned
## rotation_check.py, unchanged). uma-as runs on a fresh Postgres so the recreate keeps
## the grant; the enforcement point stays up and must learn the new key from a failed
## signature. Every exit after the first change restores the memory store and the
## original key, and a restore that fails fails the check. Waits are bounded.
.PHONY: rotation-check
rotation-check:
	@scripts/rotation-check.sh

## Phase D: the pinned intent, assurance, consequence, first-party and sub-agent checks,
## unchanged. Each edits and restores her policy, so they run one at a time.
.PHONY: intent-check assurance-check consequence-check first-party-check subagent-check
intent-check assurance-check consequence-check first-party-check subagent-check:
	docker compose --profile test run --rm $@

## Phase E1: resource-server establishment and separate owner authorities.
.PHONY: establishment-check multi-owner-check
establishment-check multi-owner-check:
	docker compose --profile test run --rm $@

## Phase E2: charter, shared resources and attested clearance.
.PHONY: org-check clearance-check rego-test joint-check
org-check clearance-check joint-check xaa-check:
	docker compose --profile test run --rm $@

rego-test:
	@docker run --rm --platform linux/amd64 -v "$(CURDIR)/conformance/upstream/lib:/v:ro" openpolicyagent/opa:1.4.2 eval --fail-defined \
		-d /v/pattern_vectors.json \
		'some v in data.vectors; glob.match(v.pattern, ["/"], v.resource) != v.match' \
		>/dev/null \
		&& echo "rego: every shared pattern vector matches as the vectors say" \
		|| { echo "rego: a shared pattern vector does not match as the vectors say"; exit 1; }

## check-live: one gate at a time, in this order, stopping at the first
## failure, whatever -j the caller passed.
LIVE_GATES = shim-test ts-agent-check decline-check demo-acts-a demo-acts-b flow-check \
	embedded-check smoke-alice fixture rotation-check store-test \
	intent-check assurance-check consequence-check first-party-check subagent-check \
	demo-all-sim establishment-check multi-owner-check org-check clearance-check rego-test joint-check xaa-check smoke-test \
	adapter-check kwaai-check paios-check n8n-check owner-cli-check portal-check
check-live:
	+@for gate in $(LIVE_GATES); do \
		echo "=== $$gate"; \
		$(MAKE) --no-print-directory -j1 $$gate || { echo "=== $$gate FAILED"; exit 1; }; \
	done

## adapter: the agent-shim over stateless streamable HTTP inside the lab network
## (agent-shim:9030/mcp). Ready once it logs that it is listening, within 60s, and
## failed if the container exits first. The adapter-check gate lands in Phase F.
.PHONY: adapter adapter-down
adapter:
	docker compose --profile adapter up -d agent-shim
	@printf "Waiting for the adapter"; \
	for i in $$(seq 1 60); do \
		docker compose logs agent-shim 2>/dev/null | grep -q "listening on" \
			&& { echo " ready"; exit 0; }; \
		[ "$$(docker compose ps --status running -q agent-shim)" ] \
			|| { echo " exited"; docker compose logs --tail 20 agent-shim; exit 1; }; \
		printf "."; sleep 1; \
	done; echo " not ready after 60s"; docker compose logs --tail 20 agent-shim; exit 1

adapter-down:
	docker compose --profile adapter stop agent-shim >/dev/null 2>&1 || true
	docker compose --profile adapter rm -f agent-shim >/dev/null 2>&1 || true
	@echo "==> adapter stopped"

## vectors: regenerate CPython ground-truth vectors from the pinned upstream modules
## (aauth-signing as the pinned aauth-test installs it). The pure AS policy modules
## (policy, assurance, introduction) are vendored for this and imported from there.
.PHONY: vectors
vectors:
	docker run --rm -v "$(PWD)/conformance/upstream/lib:/u4a/lib:ro" \
		-v "$(PWD)/conformance/upstream/services/uma-as:/u4a/as:ro" \
		-v "$(PWD)/scripts/vectors:/u4a/vectors:ro" \
		-v "$(PWD)/lib/uma4a-common/src/test/resources/pinned:/out" \
		-e PYTHONPATH=/u4a/lib:/u4a/as python:3.12.12-slim \
		sh -c "pip install -q 'cryptography==50.0.2' 'pyjwt[crypto]==2.15.1' \
			'aauth==0.3.2' 'aauth-signing==0.1.3' && python /u4a/vectors/generate.py /out"


## Phase F: the adapter, owner device, n8n sidecar, and owner CLI.
.PHONY: adapter-check fetch-paios kwaai-check paios paios-down paios-check paios-logs n8n-check owner owner-cli-check portal-check
adapter-check: adapter
	docker compose --profile adapter run --rm adapter-check

fetch-paios:
	@mkdir -p aauth/upstream
	@if [ ! -d aauth/upstream/paios/.git ]; then \
		git clone https://github.com/pAI-OS/paios aauth/upstream/paios; \
	fi
	@git -C aauth/upstream/paios cat-file -e '$(PAIOS_REF)^{commit}' 2>/dev/null \
		|| git -C aauth/upstream/paios fetch -q origin $(PAIOS_REF)
	@git -C aauth/upstream/paios checkout --detach -q $(PAIOS_REF)

kwaai-check: owner-key
	docker compose --profile test run --rm kwaai-check

paios: fetch-paios owner-key
	docker compose --profile kwaai up -d --build paios

paios-down:
	docker compose --profile kwaai stop paios

paios-logs:
	docker compose logs -f paios

paios-check: fetch-paios owner-key
	@scripts/paios-check.sh

n8n-check: owner-key
	docker compose --profile n8n-lab up -d --build --wait n8n-sidecar
	docker compose --profile n8n-lab run --rm n8n-check

owner:
	$(FIXTURE) --profile owner run --build --rm --no-deps owner-cli $(ARGS)

owner-cli-check:
	@scripts/owner-cli-check.sh '$(FIXTURE_PROJECT)'

portal-check:
	docker compose --profile test run --rm portal-check
