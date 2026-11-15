# ADR-0001: Modular monolith with isolated workers
Status: accepted
Context: One or two builders; need clear module boundaries and strong isolation of scanning from control state.
Decision: One deployable control plane with strict module boundaries; scan workers run as separate, isolated processes/containers. No microservices.
Consequences: Simpler deploys and tests; module boundaries enforced by import rules and tests; the scan plane can scale independently.
