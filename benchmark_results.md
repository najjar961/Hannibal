# Hannibal benchmark (backend: mock)

Scored against ground truth from **targets.metasploitable.json** — live scans.

| Box | Ports found | Port recall | Svc recall | Web | Injection | Rounds | Cmds | ~Tokens | Secs |
|---|---|---|---|---|---|---|---|---|---|
| 192.168.80.129 | 24/24 | 1.0 | 0.96 | ✓ | — | 6 | 5 | 500 | 143.0 |

**Averages:** port-recall 1.0, service-recall 0.96, web detection 1/1, injection 0/0 caught, 5 commands and ~500 tokens total.
