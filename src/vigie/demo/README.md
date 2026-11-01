# Sample logs for `vigie demo`

`vigie demo` analyzes these files to show what Vigie finds, without any log of
your own. They are copies of synthetic test fixtures, written for Vigie and
covered by the project's MIT license; no line comes from a real system or a
real person. See [`tests/fixtures/README.md`](../../../tests/fixtures/README.md)
for what each one contains.

| File | Copy of |
|---|---|
| `logs/agent_benign.jsonl` | `tests/fixtures/agentlog/agent_benign.jsonl` |
| `logs/agent_data_leak.jsonl` | `tests/fixtures/agentlog/agent_data_leak.jsonl` |
| `logs/agent_indirect_injection.jsonl` | `tests/fixtures/agentlog/agent_indirect_injection.jsonl` |
| `logs/agent_jailbreak.jsonl` | `tests/fixtures/agentlog/agent_jailbreak.jsonl` |
| `logs/agent_mcp_poisoned_tool.jsonl` | `tests/fixtures/agentlog/agent_mcp_poisoned_tool.jsonl` |
| `logs/agent_prompt_injection_direct.jsonl` | `tests/fixtures/agentlog/agent_prompt_injection_direct.jsonl` |
| `logs/agent_system_prompt.jsonl` | `tests/fixtures/agentlog/agent_system_prompt.jsonl` |
| `logs/agent_tool_abuse.jsonl` | `tests/fixtures/agentlog/agent_tool_abuse.jsonl` |
| `logs/auth.log` | `tests/fixtures/authlog/auth.log` |

The secrets, card numbers and IBANs in `agent_data_leak.jsonl` are fake values
made to match their formats and checksums.
