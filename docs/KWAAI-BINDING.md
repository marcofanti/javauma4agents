# Kwaai and the owner device key

The owner can answer her authorization server with her device key alongside
her portal session. The ability uses an RFC 9421 signature on the owner API.
Her public key is enrolled with the Java authorization server. The private
key stays with the owner client.

```sh
make up
make kwaai-check
make paios-check
```

`kwaai-check` runs the pinned binding probe through the full Java stack.
`paios-check` builds pAI-OS at `b65d858f12c1da472176829af4b533a9e7c246e2`
and installs the pinned ability. The fixture first gives a named test agent
an explicit owner approval. The unchanged checker then exercises the real pAI-OS loader and the
ability. Its launcher supplies the admitted agent's fixture keystore,
and the supplemental cases check the same ability's log. The unfamiliar agent is refused.
The admitted agent can use a standing-consent read tier and is refused on an
ask-me operation.

Use `make paios` to run the lab ability interactively with
`PAIOS_AUTO_TIERS=tier1` by default. Watch it with `make paios-logs` and
stop it with `make paios-down` to return owner decisions to the portal.
