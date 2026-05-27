# Integrations

## MCPGuard Policy Export

AIShield can generate YAML policies for [MCPGuard](https://github.com/Carlos-Projects/mcpguard):

```python
from aishield.export.mcpguard import generate_mcpguard_policy

policy = generate_mcpguard_policy(risk_score=65)
# Use with MCPGuard to restrict dangerous MCP tools
```

## mcp-taxonomy Adapter

Findings can be mapped to the shared [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy):

```python
from aishield.taxonomy import aishield_finding_to_taxonomy

event = aishield_finding_to_taxonomy(finding)
# Compatible with MCPscop dashboard
```

## Related Projects

| Project | Description |
|---------|-------------|
| [MCPGuard](https://github.com/Carlos-Projects/mcpguard) | Runtime security proxy for MCP/A2A |
| [MCPwn](https://github.com/Carlos-Projects/mcpwn) | Offensive security testing for MCP |
| [Palisade Scanner](https://github.com/Carlos-Projects/palisade-scanner) | Scan web content for prompt injection |
| [reverse-abliterate](https://github.com/Carlos-Projects/reverse-abliterate) | Detect and reverse model abliteration |
| [ModelChain](https://github.com/Carlos-Projects/modelchain) | SBOM generator for AI models |
| [DataShield](https://github.com/Carlos-Projects/datashield) | Privacy-preserving data sanitization |
| [MCPscop](https://github.com/Carlos-Projects/mcpscope) | Unified security dashboard for MCP scanners |
