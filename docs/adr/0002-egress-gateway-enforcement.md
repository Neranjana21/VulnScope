# ADR-0002: Enforce scope at the network layer through an egress gateway
Status: accepted
Context: App-level scope checks can be bypassed by adapter bugs or by the wrapped tools themselves.
Decision: Scan workers have no direct egress. All target traffic goes through a gateway that holds the engagement allowlist, resolves DNS itself, pins the resolved IP per connection, re-checks every redirect, always blocks link-local and metadata ranges, and fails closed.
Consequences: Scope holds even if an adapter misbehaves; added latency and one more component; revocation removes the allowlist entry to stop running work.
