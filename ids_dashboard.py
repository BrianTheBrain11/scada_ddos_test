#!/usr/bin/env python3
"""IDS/control dashboard for the SCADA DDoS testbed.

The dashboard can run standalone, or scada_topology.py can attach a control
hook so browser actions start and stop real Mininet host processes.
"""

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


STARTED_AT = time.time()
CONTROL_HOOK = None
CONTROL_STATUS = {
    "mode": "standalone",
    "last_action": "none",
    "last_error": "",
    "services": {},
}
CONTROL_LOCK = threading.Lock()


def set_control_hook(hook, mode="managed"):
    global CONTROL_HOOK
    CONTROL_HOOK = hook
    set_control_status(mode=mode)


def set_control_status(**updates):
    with CONTROL_LOCK:
        CONTROL_STATUS.update(updates)


def control_status_snapshot():
    with CONTROL_LOCK:
        return dict(CONTROL_STATUS)


class DashboardState:
    def __init__(self):
        self.started_at = STARTED_AT
        self.frames_allowed = 0
        self.successful_rate = 0
        self.rejected_rate = 0
        self.timeout_rate = 0
        self.connection_rate = 0
        self.modbus_frame_rate = 0
        self.external_api_rate = 0
        self.bad_control_rate = 0
        self.observed_sources = []
        self.metric_source = "none"
        self.frames_blocked_rate = 0
        self.frames_blocked_malformed = 0
        self.connections_blocked = 0
        self.last_update = STARTED_AT
        self.config = {
            "attack_profile": "modbus_read_flood",
            "burst_rate": 50,
            "attack_connections_per_second": 10,
            "duration_seconds": 30,
            "wait_seconds": 10,
            "connection_limiting_enabled": False,
            "rate_limiting_enabled": False,
            "natural_network_activity": False,
            "conn_threshold": 20,
            "frame_rate_limit": 100,
            "allowlist": "10.0.2.20",
            "state_api_url": "http://10.0.1.20:8080/api/state",
            "attack_status": "idle",
        }

    def update_config(self, updates):
        previous = dict(self.config)
        fields = {
            "attack_profile": str,
            "burst_rate": int,
            "attack_connections_per_second": int,
            "duration_seconds": int,
            "wait_seconds": int,
            "connection_limiting_enabled": bool,
            "rate_limiting_enabled": bool,
            "natural_network_activity": bool,
            "conn_threshold": int,
            "frame_rate_limit": int,
            "allowlist": str,
            "state_api_url": str,
            "attack_status": str,
        }
        for key, caster in fields.items():
            if key not in updates:
                continue
            value = updates[key]
            if caster is bool:
                self.config[key] = bool(value)
            elif caster is int:
                self.config[key] = max(0, int(value))
            else:
                self.config[key] = str(value)

        if CONTROL_HOOK:
            try:
                CONTROL_HOOK(previous, dict(self.config))
            except Exception as exc:
                set_control_status(last_error=str(exc))
                raise

        return dict(self.config)

    def update_observed_activity(self, connection_rate=0, modbus_frame_rate=0, external_api_rate=0, bad_control_rate=0, successful_rate=None, rejected_rate=None, timeout_rate=None, observed_sources=None, frames_allowed=None, metric_source="controller"):
        self.successful_rate = max(0, int(connection_rate if successful_rate is None else successful_rate))
        self.rejected_rate = max(0, int(bad_control_rate if rejected_rate is None else rejected_rate))
        self.timeout_rate = max(0, int(0 if timeout_rate is None else timeout_rate))
        self.connection_rate = self.successful_rate
        self.modbus_frame_rate = max(0, int(modbus_frame_rate))
        self.external_api_rate = max(0, int(external_api_rate))
        self.bad_control_rate = self.rejected_rate
        self.observed_sources = list(observed_sources or [])
        self.metric_source = metric_source
        if frames_allowed is not None:
            self.frames_allowed = max(0, int(frames_allowed))

    def snapshot(self):
        now = time.time()
        elapsed = max(0.0, now - self.started_at)
        self.last_update = now

        return {
            "uptime_seconds": round(elapsed, 1),
            "severity": "GREEN",
            "successful_rate": self.successful_rate,
            "rejected_rate": self.rejected_rate,
            "timeout_rate": self.timeout_rate,
            "connection_rate": self.connection_rate,
            "modbus_frame_rate": self.modbus_frame_rate,
            "external_api_rate": self.external_api_rate,
            "bad_control_rate": self.bad_control_rate,
            "malformed_rate": self.bad_control_rate,
            "frames_allowed": self.frames_allowed,
            "frames_blocked_rate": self.frames_blocked_rate,
            "frames_blocked_malformed": self.frames_blocked_malformed,
            "connections_blocked": self.connections_blocked,
            "plc_target": "10.0.2.30:502",
            "observed_sources": list(self.observed_sources),
            "metric_source": self.metric_source,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "config": dict(self.config),
            "control_status": control_status_snapshot(),
            "energy_assets": {
                "solar_source": "solar inverter/source simulator",
                "battery": "battery energy storage simulator at 10.0.2.50",
                "control_panel": "HMI/control panel at 10.0.2.20",
                "plc": "energy controller PLC at 10.0.2.30",
                "external_state_api": "external energy state API at 10.0.1.20:8080",
                "external_battery_path": "10.0.1.20 -> s1 -> gateway -> s2 -> 10.0.2.50",
            },
        }


STATE = DashboardState()


HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SCADA IDS Dashboard</title>
  <style>
    :root { color-scheme: dark; --bg:#101216; --panel:#1a2028; --panel-2:#242c37; --text:#f4f7fb; --muted:#aab4c2; --line:#364152; --green:#3ddc84; --yellow:#ffd166; --red:#ff5c70; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; background:var(--bg); color:var(--text); font-family:Arial, Helvetica, sans-serif; }
    header { border-bottom:1px solid var(--line); background:#151922; padding:18px 22px; display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap; }
    h1 { margin:0; font-size:22px; font-weight:700; letter-spacing:0; }
    main { max-width:1240px; margin:0 auto; padding:22px; }
    .status { display:flex; gap:10px; align-items:center; color:var(--muted); font-size:14px; flex-wrap:wrap; }
    .badge { border:1px solid var(--line); background:var(--panel-2); color:var(--text); border-radius:6px; padding:7px 9px; min-width:88px; text-align:center; font-weight:700; }
    .badge.green { color:var(--green); } .badge.yellow { color:var(--yellow); } .badge.red { color:var(--red); }
    .grid { display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:14px; margin-bottom:14px; }
    .metric, .section { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }
    .metric label { display:block; color:var(--muted); font-size:13px; margin-bottom:9px; }
    .metric strong { display:block; font-size:28px; line-height:1.1; letter-spacing:0; }
    .metric span { display:block; color:var(--muted); margin-top:7px; font-size:12px; }
    .layout { display:grid; gap:14px; align-items:start; }
    .stack { display:grid; gap:14px; }
    h2 { margin:0 0 14px; font-size:16px; letter-spacing:0; }
    .table { display:grid; gap:9px; font-size:14px; }
    .row { display:flex; justify-content:space-between; gap:14px; border-bottom:1px solid var(--line); padding-bottom:9px; }
    .row:last-child { border-bottom:0; padding-bottom:0; }
    .row span:first-child { color:var(--muted); }
    .row span:last-child { text-align:right; font-weight:700; overflow-wrap:anywhere; }
    .chart-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:10px; flex-wrap:wrap; }
    .legend { display:flex; gap:12px; align-items:center; flex-wrap:wrap; color:var(--muted); font-size:12px; }
    .legend-item { display:inline-flex; align-items:center; gap:6px; white-space:nowrap; }
    .swatch { width:18px; height:3px; border-radius:2px; display:inline-block; }
    .swatch.connections { background:#5aa9ff; }
    .swatch.rejected { background:#ff5c70; }
    .swatch.timeout { background:#ffd166; }
    canvas { width:100%; height:260px; display:block; background:#121721; border:1px solid var(--line); border-radius:6px; }
    form { display:grid; gap:12px; }
    .attack-grid { display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:12px; }
    .attack-wide { grid-column:1 / -1; }
    .subsection h3 { margin:4px 0 0; color:var(--text); font-size:14px; letter-spacing:0; }
    .field { display:grid; gap:6px; }
    .field label { color:var(--muted); font-size:13px; }
    input, select { width:100%; border:1px solid var(--line); background:#111721; color:var(--text); border-radius:6px; padding:9px 10px; font:inherit; }
    .checks { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
    .check { display:flex; align-items:center; gap:8px; border:1px solid var(--line); background:#111721; border-radius:6px; padding:9px 10px; color:var(--muted); font-size:13px; }
    .check input { width:auto; }
    .actions { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
    button { border:1px solid var(--line); border-radius:6px; background:var(--panel-2); color:var(--text); padding:10px 12px; font-weight:700; cursor:pointer; }
    button.primary { background:#1f6feb; border-color:#2f81f7; } button.stop { background:#7f1d2d; border-color:#b33a4b; }
    @media (max-width:960px) { .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } .attack-grid { grid-template-columns:1fr; } }
    @media (max-width:520px) { main { padding:14px; } .grid { grid-template-columns:1fr; } .checks, .actions { grid-template-columns:1fr; } header { padding:14px; } }
  </style>
</head>
<body>
  <header><h1>SCADA IDS Dashboard</h1><div class="status"><span>Target <strong id="plcTarget">10.0.2.30:502</strong></span><span id="attackStatus" class="badge">IDLE</span><span id="severity" class="badge green">GREEN</span></div></header>
  <main>
    <section class="grid" aria-label="Primary metrics">
      <div class="metric"><label>Successful proper traffic</label><strong id="successfulRate">0</strong><span>connections/sec</span></div>
      <div class="metric"><label>Rejected malformed traffic</label><strong id="rejectedRate">0</strong><span>packets/sec</span></div>
      <div class="metric"><label>Timed out / dropped</label><strong id="timeoutRate">0</strong><span>requests/sec</span></div>
      <div class="metric"><label>Successful total</label><strong id="framesAllowed">0</strong><span>total observed</span></div>
    </section>
    <section class="layout">
      <div class="stack">
        <div class="section"><div class="chart-head"><h2>Traffic Window</h2><div class="legend"><span class="legend-item"><span class="swatch connections"></span>Successful proper traffic</span><span class="legend-item"><span class="swatch rejected"></span>Rejected malformed traffic</span><span class="legend-item"><span class="swatch timeout"></span>Timed out / dropped</span></div></div><canvas id="chart" width="900" height="260"></canvas></div>
        <div class="section"><h2>Defense Status</h2><div class="table">
          <div class="row"><span>Connection limiting</span><span id="connectionLimitEnabled">disabled</span></div>
          <div class="row"><span>Rate limiting</span><span id="rateLimitEnabled">disabled</span></div>
          <div class="row"><span>Frames blocked by rate</span><span id="blockedRate">0</span></div>
          <div class="row"><span>Frames blocked malformed</span><span id="blockedMalformed">0</span></div>
          <div class="row"><span>Connections blocked</span><span id="connectionsBlocked">0</span></div>
          <div class="row"><span>Observed sources</span><span id="sources">none</span></div>
          <div class="row"><span>Metric source</span><span id="metricSource">none</span></div>
          <div class="row"><span>Natural activity</span><span id="naturalActivityStatus">disabled</span></div>
          <div class="row"><span>External state API</span><span id="stateApiUrl">unknown</span></div>
          <div class="row"><span>Controller mode</span><span id="controlMode">standalone</span></div>
          <div class="row"><span>Controller action</span><span id="controlAction">none</span></div>
          <div class="row"><span>Updated</span><span id="updatedAt">never</span></div>
        </div></div>
      </div>
      <div class="section"><h2>Malformed Packet Flood DDoS</h2><form id="controlForm"><div class="attack-grid">
        <div class="subsection attack-wide"><h3>Attack Load</h3></div>
        <input id="attackProfile" type="hidden" value="bad_battery_control">
        <div class="field"><label for="attackCps">Malformed packets/sec</label><input id="attackCps" type="number" min="1" max="5000" step="1"></div>
        <div class="field"><label for="durationSeconds">Duration seconds</label><input id="durationSeconds" type="number" min="1" max="3600" step="1"></div>
        <div class="field"><label for="waitSeconds">Wait seconds</label><input id="waitSeconds" type="number" min="0" max="3600" step="1"></div>
        <div class="subsection attack-wide"><h3>Normal Traffic</h3></div>
        <div class="checks attack-wide"><label class="check"><input id="naturalActivityToggle" type="checkbox" onchange="saveConfig(null)"> Natural Network Activity</label></div>
        <div class="field"><label for="stateApiUrlInput">External state source</label><input id="stateApiUrlInput" type="text"></div>
        <div class="subsection attack-wide"><h3>Mitigation Policy</h3></div>
        <div class="checks attack-wide"><label class="check"><input id="connectionLimitToggle" type="checkbox"> Enable connection limiting</label><label class="check"><input id="rateLimitToggle" type="checkbox"> Enable rate limiting</label></div>
        <div class="field"><label for="connThreshold">Max connections/sec per source</label><input id="connThreshold" type="number" min="0" max="10000" step="1"></div>
        <div class="field"><label for="frameRateLimit">Max malformed packets/sec</label><input id="frameRateLimit" type="number" min="0" max="100000" step="1"></div>
        <div class="field"><label for="allowlist">Allowed normal source</label><input id="allowlist" type="text"></div>
        <div class="actions attack-wide"><button class="primary" type="button" onclick="saveConfig('running')">Start Malformed Packet Flood DDoS</button><button class="stop" type="button" onclick="saveConfig('idle')">Stop DDoS</button></div>
        <button class="attack-wide" type="button" onclick="saveConfig(null)">Save Settings</button></div>
      </form></div>
    </section>
  </main>
  <script>
    const history = []; const maxPoints = 60; const canvas = document.getElementById('chart'); const ctx = canvas.getContext('2d'); let formLoaded = false;
    function setText(id, value) { document.getElementById(id).textContent = value; }
    function setSeverity(value) { const el = document.getElementById('severity'); el.textContent = value; el.className = 'badge ' + value.toLowerCase(); }
    function loadForm(config) { if (formLoaded) return; document.getElementById('attackCps').value = config.attack_connections_per_second; document.getElementById('durationSeconds').value = config.duration_seconds; document.getElementById('waitSeconds').value = config.wait_seconds; document.getElementById('connectionLimitToggle').checked = config.connection_limiting_enabled;
      document.getElementById('rateLimitToggle').checked = config.rate_limiting_enabled; document.getElementById('naturalActivityToggle').checked = config.natural_network_activity; document.getElementById('connThreshold').value = config.conn_threshold; document.getElementById('frameRateLimit').value = config.frame_rate_limit; document.getElementById('allowlist').value = config.allowlist; document.getElementById('stateApiUrlInput').value = config.state_api_url; formLoaded = true; }
    function currentConfig(status) { const config = { attack_profile: 'bad_battery_control', attack_connections_per_second: Number(document.getElementById('attackCps').value), duration_seconds: Number(document.getElementById('durationSeconds').value), wait_seconds: Number(document.getElementById('waitSeconds').value), connection_limiting_enabled: document.getElementById('connectionLimitToggle').checked,
        rate_limiting_enabled: document.getElementById('rateLimitToggle').checked, natural_network_activity: document.getElementById('naturalActivityToggle').checked, conn_threshold: Number(document.getElementById('connThreshold').value), frame_rate_limit: Number(document.getElementById('frameRateLimit').value), allowlist: document.getElementById('allowlist').value, state_api_url: document.getElementById('stateApiUrlInput').value }; if (status !== null) config.attack_status = status; return config; }
    async function saveConfig(status) { await fetch('/api/config', { method:'POST', headers:{ 'Content-Type':'application/json' }, body:JSON.stringify(currentConfig(status)) }); await refresh(); }
    function drawChart() {
      const w = canvas.width, h = canvas.height;
      const left = 58, right = 16, top = 26, bottom = 32;
      const plotW = w - left - right;
      const plotH = h - top - bottom;
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = '#121721';
      ctx.fillRect(0, 0, w, h);

      const latest = history.length ? history[history.length - 1] : { successful_rate: 0, rejected_rate: 0, timeout_rate: 0 };
      const maxValue = Math.max(10, ...history.map(p => Math.max(p.successful_rate, p.rejected_rate, p.timeout_rate)));

      ctx.strokeStyle = '#2e3746';
      ctx.fillStyle = '#a8b1bf';
      ctx.font = '12px Arial';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      for (let i = 0; i <= 4; i++) {
        const value = Math.round(maxValue - i * (maxValue / 4));
        const y = top + i * (plotH / 4);
        ctx.beginPath();
        ctx.moveTo(left, y);
        ctx.lineTo(w - right, y);
        ctx.stroke();
        ctx.fillText(String(value), left - 10, y);
      }

      ctx.textAlign = 'left';
      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = '#a8b1bf';
      ctx.fillText(`current: success ${latest.successful_rate}/s   rejected ${latest.rejected_rate}/s   timed out/dropped ${latest.timeout_rate}/s`, left, 18);

      if (history.length < 2) return;
      function plot(key, color) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.beginPath();
        history.forEach((point, index) => {
          const x = left + index * (plotW / Math.max(1, maxPoints - 1));
          const y = top + plotH - (point[key] / maxValue) * plotH;
          if (index === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });
        ctx.stroke();
      }
      plot('successful_rate', '#5aa9ff');
      plot('rejected_rate', '#ff5c70');
      plot('timeout_rate', '#ffd166');
    }
    async function refresh() { const response = await fetch('/api/metrics', { cache:'no-store' }); const data = await response.json(); loadForm(data.config); setText('plcTarget', data.plc_target); setText('successfulRate', data.successful_rate); setText('rejectedRate', data.rejected_rate); setText('timeoutRate', data.timeout_rate); setText('framesAllowed', data.frames_allowed); setText('connectionLimitEnabled', data.config.connection_limiting_enabled ? 'enabled' : 'disabled'); setText('rateLimitEnabled', data.config.rate_limiting_enabled ? 'enabled' : 'disabled'); setText('blockedRate', data.frames_blocked_rate); setText('blockedMalformed', data.frames_blocked_malformed); setText('connectionsBlocked', data.connections_blocked); setText('sources', data.observed_sources.length ? data.observed_sources.join(', ') : 'none'); setText('metricSource', data.metric_source); setText('naturalActivityStatus', data.config.natural_network_activity ? 'enabled' : 'disabled'); setText('stateApiUrl', data.config.state_api_url); setText('controlMode', data.control_status.mode); setText('controlAction', data.control_status.last_error || data.control_status.last_action); setText('updatedAt', data.updated_at); setText('attackStatus', data.config.attack_status.toUpperCase()); setSeverity(data.severity); history.push(data); if (history.length > maxPoints) history.shift(); drawChart(); }
    refresh(); setInterval(refresh, 1000);
  </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(HTML.encode("utf-8"))
            return
        if path == "/api/metrics":
            self.write_json(STATE.snapshot())
            return
        if path == "/api/config":
            self.write_json(STATE.config)
            return
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"not found\n")

    def do_POST(self):
        if urlparse(self.path).path != "/api/config":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b"{}"
        try:
            updates = json.loads(raw_body.decode("utf-8"))
            config = STATE.update_config(updates)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(exc)}).encode("utf-8"))
            return
        self.write_json(config)

    def write_json(self, value):
        payload = json.dumps(value).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"IDS dashboard: {self.address_string()} - {fmt % args}", flush=True)


def serve(host="0.0.0.0", port=5000):
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"IDS dashboard listening on http://{host}:{port}", flush=True)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Serve the SCADA IDS/control dashboard")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
















