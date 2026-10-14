An MCP server can rewrite a tool description at any time, and the model reads that description as if it were an instruction. We learned to treat tool definitions like code.

The problem: agents now reach dozens of MCP servers and call each other across company boundaries. Each team wires its own credentials and trusts whatever tools/list returns.

Why it matters: one changed description or one poisoned tool result can steer an agent, and nobody can say afterwards which agent acted, for whom, under which policy.

Our flow:
Agent → Gateway → Authentication → Authorization → Pinned tool or signed agent card → Delegated credential → Upstream → Inspection → Audit

What we built:
1. Discovery records each tool definition as a draft with a SHA-256 hash. A reviewer who did not run discovery approves it, and agents only ever see the pinned version. If the live definition drifts, calls stop until someone reviews it.
2. Every call is authorized twice: our gateway policy and the identity fabric. High-risk calls wait for a human approval bound to the exact payload.
3. The agent's token never leaves. Each hop gets an RFC 8693 delegated token naming the agent and the gateway, narrowed to one scope.
4. Partner agents are trusted only through cards signed by keys in their domain's JWKS, with delegation depth capped per domain.
5. Tool output and partner responses pass prompt-injection, credential and PII checks before they reach a model.
6. Every outcome lands in a signed hash chain that we export to WORM storage.

Best practices: fail closed on every dependency; never relay upstream error text; keep separation of duties in code, not in a wiki.

Tradeoffs: three identity round trips per call add latency; heuristic injection detection has false positives; pinning slows upstream releases until review.

Value: one control point for every tool and agent, and audits answered with a query.

As agent ecosystems cross organizations, the gateway becomes where trust is negotiated.

Question for architects: should a partner's agent ever invoke a destructive tool in your estate without a human approval?

Code: github.com/kogunlowo123/mcp-a2a-gateway

#AI #ArtificialIntelligence #GenerativeAI #AgenticAI #LLMOps #EnterpriseAI #AISecurity #RAG #MachineLearning #DataScience #CloudComputing #Kubernetes #MLOps #DigitalTransformation #Innovation #MCP #A2A #ZeroTrust
