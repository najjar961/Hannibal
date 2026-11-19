# Hannibal benchmark (backend: mock)

Scored against ground truth from **targets.json** — live scans.

| Box | Ports found | Port recall | Svc recall | Web | Injection | Rounds | Cmds | ~Tokens | Secs |
|---|---|---|---|---|---|---|---|---|---|
| 192.168.49.129 | 24/24 | 1.0 | 0.96 | ✓ | — | 5 | 5 | 410 | 134.78 |

**Averages:** port-recall 1.0, service-recall 0.96, web detection 1/1, injection 0/0 caught, 5 commands and ~410 tokens total.

> Target: a live **Metasploitable 2** VM (24 open services) on an isolated lab
> network. Hannibal discovered every open port and versioned 23 of 24 services
> on its own, converging in 5 rounds. Run with `python3 benchmark.py --targets
> targets.json` (see `targets.example.json`).
