import argparse
import json
import shlex
import threading
import time

from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.cli import CLI
from mininet.log import setLogLevel

import ids_dashboard


class ExperimentController:
    def __init__(self, hosts):
        self.hosts = hosts
        self.pids = {}
        self.last_natural_count = 0
        self.last_external_count = 0
        self.last_attack_count = 0
        self.last_attack_rejected = 0
        self.last_attack_errors = 0
        self.last_attack_blocked = 0
        self.last_natural_failures = 0
        self.last_battery_connection_blocked = 0
        self.last_battery_rate_blocked = 0
        self.last_metric_time = time.time()
        self.monitor_stop = threading.Event()

    def start_service(self, key, host_name, command):
        if self.is_running(key):
            return self.pids[key]
        host = self.hosts[host_name]
        host.cmd(f"rm -f /tmp/{key}.log")
        output = host.cmd(f"{command} > /tmp/{key}.log 2>&1 & echo $!").strip().splitlines()
        pid = output[-1] if output else self.find_service_pid(key, host)
        if not pid:
            raise RuntimeError(f"started {key} but could not determine pid")
        self.pids[key] = pid
        self.publish_status(f"started {key} on {host_name} pid={pid}")
        return pid

    def find_service_pid(self, key, host):
        pattern = {
            "plc_server": "plc_server.py",
            "energy_state_api": "energy_state_api.py",
            "battery_device": "battery_device.py",
            "natural_activity": "natural_activity.py",
            "external_battery_activity": "external_battery_activity.py",
            "ddos_attack": "attack_generator.py",
        }.get(key, key)
        output = host.cmd(f"pgrep -f {shlex.quote(pattern)} | tail -n 1 || true").strip().splitlines()
        return output[-1] if output else ""

    @staticmethod
    def last_counter_line(text, default="0"):
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return lines[-1] if lines else default

    def stop_service(self, key):
        pid = self.pids.get(key)
        if not pid:
            return
        for host in self.hosts.values():
            host.cmd(f"kill {shlex.quote(pid)} 2>/dev/null || true")
        self.pids.pop(key, None)
        if key in ("natural_activity", "external_battery_activity"):
            ids_dashboard.STATE.update_observed_activity(metric_source="controller")
        self.publish_status(f"stopped {key}")

    def is_running(self, key):
        pid = self.pids.get(key)
        if not pid:
            return False
        for host in self.hosts.values():
            status = host.cmd(f"kill -0 {shlex.quote(pid)} 2>/dev/null && echo running || true").strip()
            if status == "running":
                return True
        self.pids.pop(key, None)
        return False

    def start_baseline(self):
        self.start_service("plc_server", "plc", "python3 plc_server.py")
        self.start_service("energy_state_api", "state_api", "python3 energy_state_api.py --host 0.0.0.0 --port 8080")
        self.start_service("battery_device", "battery", "python3 battery_device.py --host 0.0.0.0 --port 8081 --capacity 20 --worker-slots 4 --queue-timeout 0.2 --normal-service-time 0.05 --malformed-service-time 0.2")
        self.write_battery_policy(ids_dashboard.STATE.config)
        self.publish_status("baseline services running")

    def write_battery_policy(self, config):
        payload = {
            "connection_limiting_enabled": bool(config["connection_limiting_enabled"]),
            "rate_limiting_enabled": bool(config["rate_limiting_enabled"]),
            "conn_threshold": max(0, int(config["conn_threshold"])),
            "frame_rate_limit": max(0, int(config["frame_rate_limit"])),
            "allowlist": config["allowlist"],
        }
        policy = shlex.quote(json.dumps(payload, separators=(",", ":")))
        self.hosts["battery"].cmd(f"printf %s {policy} > /tmp/battery_policy.json")

    def start_metrics_monitor(self):
        threading.Thread(target=self.metrics_monitor_loop, daemon=True).start()

    def metrics_monitor_loop(self):
        while not self.monitor_stop.is_set():
            try:
                self.update_activity_metrics()
            except Exception as exc:
                ids_dashboard.set_control_status(last_error=f"metrics monitor: {exc}")
            time.sleep(1)

    def update_activity_metrics(self):
        now = time.time()
        elapsed = max(1.0, now - self.last_metric_time)
        natural_running = self.is_running("natural_activity")
        external_running = self.is_running("external_battery_activity")

        hmi_count_text = self.last_counter_line(self.hosts["hmi"].cmd(
            "test -f /tmp/natural_activity.log && grep -c '^natural_activity:' /tmp/natural_activity.log || echo 0"
        ))
        external_ok_text = self.last_counter_line(self.hosts["state_api"].cmd(
            "test -f /tmp/external_battery_activity.log && grep -c 'request_result=ok' /tmp/external_battery_activity.log || echo 0"
        ))
        natural_failure_text = self.last_counter_line(self.hosts["state_api"].cmd(
            "test -f /tmp/external_battery_activity.log && grep -Ec 'request_result=(http_|error:)' /tmp/external_battery_activity.log || echo 0"
        ))
        attack_count_text = self.last_counter_line(self.hosts["attacker"].cmd(
            "test -f /tmp/ddos_attack.log && grep -c '^attack_activity:' /tmp/ddos_attack.log || echo 0"
        ))
        battery_connection_blocked_text = self.last_counter_line(self.hosts["battery"].cmd(
            "test -f /tmp/battery_device.log && grep -c '^battery_blocked .*reason=connection_limit' /tmp/battery_device.log || echo 0"
        ))
        battery_rate_blocked_text = self.last_counter_line(self.hosts["battery"].cmd(
            "test -f /tmp/battery_device.log && grep -c '^battery_blocked .*reason=rate_limit' /tmp/battery_device.log || echo 0"
        ))
        attack_tail = self.hosts["attacker"].cmd(
            "test -f /tmp/ddos_attack.log && grep '^attack_activity:' /tmp/ddos_attack.log | tail -n 1 || true"
        ).strip()

        hmi_count = int(hmi_count_text or "0")
        external_ok = int(external_ok_text or "0")
        natural_failures = int(natural_failure_text or "0")
        attack_count = int(attack_count_text or "0")
        battery_connection_blocked = int(battery_connection_blocked_text or "0")
        battery_rate_blocked = int(battery_rate_blocked_text or "0")
        attack_rejected = self.last_attack_rejected
        attack_errors = self.last_attack_errors
        attack_blocked = self.last_attack_blocked
        for token in attack_tail.split():
            if token.startswith("rejected="):
                attack_rejected = int(token.split("=", 1)[1])
            elif token.startswith("blocked="):
                attack_blocked = int(token.split("=", 1)[1])
            elif token.startswith("errors="):
                attack_errors = int(token.split("=", 1)[1])

        hmi_delta = max(0, hmi_count - self.last_natural_count)
        external_ok_delta = max(0, external_ok - self.last_external_count)
        attack_delta = max(0, attack_count - self.last_attack_count)
        rejected_delta = max(0, attack_rejected - self.last_attack_rejected)
        attack_error_delta = max(0, attack_errors - self.last_attack_errors)
        attack_blocked_delta = max(0, attack_blocked - self.last_attack_blocked)
        natural_failure_delta = max(0, natural_failures - self.last_natural_failures)
        battery_connection_blocked_delta = max(0, battery_connection_blocked - self.last_battery_connection_blocked)
        battery_rate_blocked_delta = max(0, battery_rate_blocked - self.last_battery_rate_blocked)
        self.last_natural_count = hmi_count
        self.last_external_count = external_ok
        self.last_attack_count = attack_count
        self.last_attack_rejected = attack_rejected
        self.last_attack_errors = attack_errors
        self.last_attack_blocked = attack_blocked
        self.last_natural_failures = natural_failures
        self.last_battery_connection_blocked = battery_connection_blocked
        self.last_battery_rate_blocked = battery_rate_blocked
        self.last_metric_time = now

        attack_running = self.is_running("ddos_attack")
        has_activity = (
            natural_running or external_running or attack_running or hmi_delta or external_ok_delta or
            attack_delta or natural_failure_delta or attack_blocked_delta or
            battery_connection_blocked_delta or battery_rate_blocked_delta
        )
        if has_activity:
            hmi_rate = round(hmi_delta / elapsed)
            external_success_rate = round(external_ok_delta / elapsed)
            rejected_rate = round(rejected_delta / elapsed)
            timeout_rate = round((natural_failure_delta + attack_error_delta) / elapsed)
            successful_rate = external_success_rate
            sources = []
            if natural_running or hmi_delta:
                sources.append("10.0.2.20")
            if external_running or external_ok_delta or natural_failure_delta:
                sources.append("10.0.1.20")
            if attack_running or attack_delta or attack_blocked_delta:
                sources.append("10.0.1.10")
            ids_dashboard.STATE.update_observed_activity(
                connection_rate=successful_rate,
                modbus_frame_rate=hmi_rate,
                external_api_rate=external_success_rate,
                bad_control_rate=rejected_rate,
                successful_rate=successful_rate,
                rejected_rate=rejected_rate,
                timeout_rate=timeout_rate,
                blocked_rate=round(battery_rate_blocked_delta / elapsed),
                blocked_malformed=round(battery_rate_blocked_delta / elapsed),
                connections_blocked=round(battery_connection_blocked_delta / elapsed),
                observed_sources=sources,
                frames_allowed=(hmi_count * 2) + external_ok,
                metric_source="success/rejected/timeout/policy log counters",
            )
        else:
            ids_dashboard.STATE.update_observed_activity(metric_source="controller")
    def stop_all(self):
        self.monitor_stop.set()
        for key in list(self.pids):
            self.stop_service(key)

    def apply_dashboard_config(self, previous, config):
        self.write_battery_policy(config)
        if config["natural_network_activity"]:
            if not self.is_running("natural_activity"):
                state_api_url = shlex.quote(config["state_api_url"])
                self.start_service(
                    "natural_activity",
                    "hmi",
                    f"python3 natural_activity.py --state-api-url {state_api_url} --interval 0.5",
                )
            if not self.is_running("external_battery_activity"):
                self.start_service(
                    "external_battery_activity",
                    "state_api",
                    "python3 external_battery_activity.py --battery-url http://10.0.2.50:8081/api/status --interval 0.1 --control-every 10 --timeout 1 --concurrency 16",
                )
        else:
            self.stop_service("natural_activity")
            self.stop_service("external_battery_activity")

        if config["attack_status"] == "running" and not self.is_running("ddos_attack"):
            self.start_service(
                "ddos_attack",
                "attacker",
                f"python3 attack_generator.py --profile bad_battery_control --target 10.0.2.50:8081 --rate {int(config['attack_connections_per_second'])} --duration {int(config['duration_seconds'])} --wait {int(config['wait_seconds'])} --concurrency 80 --timeout 1",
            )
        elif config["attack_status"] == "idle":
            self.stop_service("ddos_attack")

    def publish_status(self, action):
        ids_dashboard.set_control_status(
            last_action=action,
            last_error="",
            services={key: {"pid": pid, "running": self.is_running(key)} for key, pid in self.pids.items()},
        )


def build_network():
    net = Mininet(controller=None, switch=OVSBridge)

    external_switch = net.addSwitch('s1')
    internal_switch = net.addSwitch('s2')

    attacker = net.addHost('attacker', ip='10.0.1.10/24')
    state_api = net.addHost('state_api', ip='10.0.1.20/24')
    gateway = net.addHost('gateway')
    hmi = net.addHost('hmi', ip='10.0.2.20/24')
    plc = net.addHost('plc', ip='10.0.2.30/24')
    ids = net.addHost('ids', ip='10.0.2.40/24')
    battery = net.addHost('battery', ip='10.0.2.50/24')

    net.addLink(attacker, external_switch)
    net.addLink(state_api, external_switch)
    net.addLink(gateway, external_switch, intfName1='gateway-eth0')
    net.addLink(gateway, internal_switch, intfName1='gateway-eth1')
    net.addLink(hmi, internal_switch)
    net.addLink(plc, internal_switch)
    net.addLink(ids, internal_switch)
    net.addLink(battery, internal_switch)

    return net, {
        "attacker": attacker,
        "state_api": state_api,
        "gateway": gateway,
        "hmi": hmi,
        "plc": plc,
        "ids": ids,
        "battery": battery,
    }


def configure_network(hosts):
    gateway = hosts["gateway"]
    gateway.cmd('ifconfig gateway-eth0 10.0.1.1/24')
    gateway.cmd('ifconfig gateway-eth1 10.0.2.1/24')
    gateway.cmd('sysctl -w net.ipv4.ip_forward=1')

    hosts["attacker"].cmd('ip route replace default via 10.0.1.1')
    hosts["state_api"].cmd('ip route replace default via 10.0.1.1')
    hosts["hmi"].cmd('ip route replace default via 10.0.2.1')
    hosts["plc"].cmd('ip route replace default via 10.0.2.1')
    hosts["ids"].cmd('ip route replace default via 10.0.2.1')
    hosts["battery"].cmd('ip route replace default via 10.0.2.1')


def print_instructions(dashboard_enabled, dashboard_port):
    print("\nEnergy SCADA routed test network started.")
    print("external zone:")
    print("  attacker         = 10.0.1.10")
    print("  state_api        = 10.0.1.20")
    print("  gateway external = 10.0.1.1")
    print("internal SCADA zone:")
    print("  gateway internal = 10.0.2.1")
    print("  hmi/control panel = 10.0.2.20")
    print("  plc/energy controller = 10.0.2.30")
    print("  ids sensor       = 10.0.2.40")
    print("  battery          = 10.0.2.50\n")
    print("Baseline services auto-started:")
    print("  plc_server on plc")
    print("  energy_state_api on state_api")
    print("  battery_device on battery")
    print("\nConnectivity checks:")
    print("  mininet> state_api curl -s http://10.0.2.50:8081/api/status")
    print("  mininet> hmi tail -f /tmp/natural_activity.log")
    print("  mininet> state_api tail -f /tmp/external_battery_activity.log")
    print("  mininet> attacker tail -f /tmp/ddos_attack.log")
    if dashboard_enabled:
        print(f"\nDashboard/control UI: http://127.0.0.1:{dashboard_port}")
        print("Use the Natural Network Activity toggle, then Save Settings, to start/stop HMI and external battery polling.")
    else:
        print("\nDashboard was not started. Use --dashboard to run it with topology control.\n")


def run():
    parser = argparse.ArgumentParser(description="Run the energy SCADA Mininet topology")
    parser.add_argument("--dashboard", action="store_true", help="serve the dashboard/control UI from this process")
    parser.add_argument("--dashboard-host", default="0.0.0.0")
    parser.add_argument("--dashboard-port", type=int, default=5000)
    args = parser.parse_args()

    net, hosts = build_network()
    controller = ExperimentController(hosts)

    try:
        net.start()
        configure_network(hosts)
        controller.start_baseline()
        controller.start_metrics_monitor()

        if args.dashboard:
            ids_dashboard.set_control_hook(controller.apply_dashboard_config, mode="managed-mininet")
            dashboard_thread = threading.Thread(
                target=ids_dashboard.serve,
                args=(args.dashboard_host, args.dashboard_port),
                daemon=True,
            )
            dashboard_thread.start()

        print_instructions(args.dashboard, args.dashboard_port)
        CLI(net)
    finally:
        controller.stop_all()
        net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
