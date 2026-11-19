# Hannibal benchmark (backend: mock)

Scored against the simulated lab's known ground truth (`hannibal/lab.py`).

| Box | Ports found | Port recall | Svc recall | Web | Injection | Rounds | Cmds | ~Tokens | Secs |
|---|---|---|---|---|---|---|---|---|---|
| 10.10.10.5 | 3/3 | 1.0 | 1.0 | ✓ | caught | 5 | 5 | 410 | 0.03 |
| 10.10.11.20 | 3/3 | 1.0 | 1.0 | ✓ | — | 5 | 5 | 410 | 0.03 |
| 10.10.11.33 | 4/4 | 1.0 | 1.0 | ✓ | caught | 5 | 5 | 410 | 0.02 |
| 10.10.10.9 | 2/2 | 1.0 | 1.0 | ✓ | — | 4 | 3 | 320 | 0.02 |

**Averages:** port-recall 1.0, service-recall 1.0, web detection 4/4, injection 2/2 caught, 18 commands and ~1550 tokens total.
