# Running Hannibal monitor as a service

`hannibal monitor` loops until stopped. To run it continuously and unattended —
so it survives logout and reboots, restarts on failure, and shuts down cleanly —
install it as a background service.

Graceful shutdown is built in: on `SIGTERM`/`SIGINT` the monitor finishes the
run it is in, flushes the baseline, writes a final heartbeat, and exits — the
state file is never left half-written.

Always point `--scope` at systems you own or are explicitly authorized to test.
The service runs recon tier only by default; the attack tier stays off.

## Linux (systemd)

A ready unit is in [`hannibal-monitor.service`](./hannibal-monitor.service).
Edit its `--scope` (and paths if you like), then:

```bash
sudo useradd --system --home /opt/hannibal --shell /usr/sbin/nologin hannibal
sudo mkdir -p /var/lib/hannibal /var/log/hannibal
sudo chown hannibal:hannibal /var/lib/hannibal /var/log/hannibal
sudo cp deploy/hannibal-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hannibal-monitor

journalctl -u hannibal-monitor -f          # live logs
cat /var/lib/hannibal/heartbeat.json       # last run + liveness
sudo systemctl stop hannibal-monitor       # graceful stop
```

## Windows

### Option A — Task Scheduler (simplest, runs at startup)

```powershell
# adjust scope, paths, and the python/hannibal invocation to your install
schtasks /Create /TN "HannibalMonitor" /SC ONSTART /RU SYSTEM /RL HIGHEST /F ^
  /TR "cmd /c python -m hannibal monitor --scope 10.0.0.0/24 --interval 3600 ^
       --state C:\hannibal\state.sqlite --alerts-file C:\hannibal\alerts.jsonl ^
       --heartbeat C:\hannibal\heartbeat.json --log-file C:\hannibal\monitor.log"

schtasks /Run /TN "HannibalMonitor"        # start now
schtasks /End /TN "HannibalMonitor"        # stop
```

Task Scheduler sends a normal termination, which the monitor handles gracefully.

### Option B — a true Windows service via NSSM

[NSSM](https://nssm.cc) wraps any command as a real service with automatic
restart and log rotation:

```powershell
nssm install HannibalMonitor python -m hannibal monitor ^
  --scope 10.0.0.0/24 --interval 3600 ^
  --state C:\hannibal\state.sqlite --heartbeat C:\hannibal\heartbeat.json
nssm set HannibalMonitor AppStdout C:\hannibal\monitor.log
nssm set HannibalMonitor AppStderr C:\hannibal\monitor.log
nssm start HannibalMonitor
```

## Checking it is alive

`--heartbeat` writes a small JSON after every run — point a healthcheck at its
`iso` timestamp:

```json
{"pid": 4122, "run": 37, "ts": 1795619163.0, "iso": "2026-11-25T14:49:00Z",
 "total": 21, "new": 0, "resolved": 0}
```

If `iso` is older than a couple of intervals, the monitor is stuck or down.
