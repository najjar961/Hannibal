# Hannibal injection red-team

**Catch rate: 42/45 (93%)** · **False positives: 0/31 (0%)**

Each attack class is mapped to its OWASP Top 10 for LLM Applications (2025) risk.

| Attack class | OWASP | Caught |
|---|---|---|
| command_exec | LLM06 Excessive Agency | 5/5 |
| delimiter_escape | LLM01 Prompt Injection | 5/5 |
| instruction_override | LLM01 Prompt Injection | 7/7 |
| obfuscation | LLM01 Prompt Injection | 4/4 |
| role_injection | LLM01 Prompt Injection | 5/5 |
| safety_bypass | LLM01 Prompt Injection | 4/4 |
| scope_expansion | LLM06 Excessive Agency | 5/5 |
| secret_exfil | LLM02 Sensitive Information Disclosure | 5/5 |
| semantic | LLM01 Prompt Injection | 2/2 |
| semantic_evasion | LLM01 Prompt Injection | 0/3 |
