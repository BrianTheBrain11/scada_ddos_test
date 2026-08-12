import argparse
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
        self.last_natural_failures = 0
        self.last_metric_time = time.time()
        self.monitor_stop = threading.Event()

    def start_service(self, key, host_name, command):
        if self.is_running(key):
            return self.pids[key]
        host = self.hosts[host_name]
        host.cmd(f"rm -f /tmp/{key}.log")
        pid = host.cmd(f"{command} > /tmp/{key}.log 2>&1 & echo $!").strip().splitlines()[-1]
        self.pids[key] = pid
        self.publish_status(f"started {key} on {host_name} pid={pid}")
        return pid

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
        self.start_service("battery_device", "battery", "python3 battery_device.py --host 0.0.0.0 --port 8081 --capacity 20 --overload-mode delay --overload-delay 3")
        self.publish_status("baseline services running")

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

        hmi_count_text = self.hosts["hmi"].cmd(
            "test -f /tmp/natural_activity.log && grep -c '^natural_activity:' /tmp/natural_activity.log || echo 0"
        ).strip().splitlines()[-1]
        external_ok_text = self.hosts["state_api"].cmd(
            "test -f /tmp/external_battery_activity.log && grep -c 'status_result=ok' /tmp/external_battery_activity.log || echo 0"
        ).strip().splitlines()[-1]
        natural_failure_text = self.hosts["state_api"].cmd(
            "test -f /tmp/external_battery_activity.log && grep -Ec 'status_result=(http_|error:)|control=(http_|error:)' /tmp/external_battery_activity.log || echo 0"
        ).strip().splitlines()[-1]
        attack_count_text = self.hosts["attacker"].cmd(
            "test -f /tmp/ddos_attack.log && grep -c '^attack_activity:' /tmp/ddos_attack.log || echo 0"
        ).strip().splitlines()[-1]
        attack_tail = self.hosts["attacker"].cmd(
            "test -f /tmp/ddos_attack.log && grep '^attack_activity:' /tmp/ddos_attack.log | tail -n 1 || true"
        ).strip()

        hmi_count = int(hmi_count_text or "0")
        external_ok = int(external_ok_text or "0")
        natural_failures = int(natural_failure_text or "0")
        attack_count = int(attack_count_text or "0")
        attack_rejected = self.last_attack_rejected
        attack_errors = self.last_attack_errors
        for token in attack_tail.split():
            if token.startswith("rejected="):
                attack_rejected = int(token.split("=", 1)[1])
            elif token.startswith("errors="):
                attack_errors = int(token.split("=", 1)[1])

        hmi_delta = max(0, hmi_count - self.last_natural_count)
        external_ok_delta = max(0, external_ok - self.last_external_count)
        attack_delta = max(0, attack_count - self.last_attack_count)
        rejected_delta = max(0, attack_rejected - self.last_attack_rejected)
        attack_error_delta = max(0, attack_errors - self.last_attack_errors)
        natural_failure_delta = max(0, natural_failures - self.last_natural_failures)
        self.last_natural_count = hmi_count
        self.last_external_count = external_ok
        self.last_attack_count = attack_count
        self.last_attack_rejected = attack_rejected
        self.last_attack_errors = attack_errors
        self.last_natural_failures = natural_failures
        self.last_metric_time = now

        attack_running = self.is_running("ddos_attack")
        if natural_running or external_running or attack_running or hmi_delta or external_ok_delta or attack_delta or natural_failure_delta:
            hmi_rate = round(hmi_delta / elapsed)
            external_success_rate = round(external_ok_delta / elapsed)
            rejected_rate = round(rejected_delta / elapsed)
            timeout_rate = round((natural_failure_delta + attack_error_delta) / elapsed)
            successful_rate = (hmi_rate * 2) + external_success_rate
            sources = []
            if natural_running or hmi_delta:
                sources.append("10.0.2.20")
            if external_running or external_ok_delta or natural_failure_delta:
                sources.append("10.0.1.20")
            if attack_running or attack_delta:
                sources.append("10.0.1.10")
            ids_dashboard.STATE.update_observed_activity(
                connection_rate=successful_rate,
                modbus_frame_rate=hmi_rate,
                external_api_rate=external_success_rate,
                bad_control_rate=rejected_rate,
                successful_rate=successful_rate,
                rejected_rate=rejected_rate,
                timeout_rate=timeout_rate,
                observed_sources=sources,
                frames_allowed=(hmi_count * 2) + external_ok,
                metric_source="success/rejected/timeout log counters",
            )
        else:
            ids_dashboard.STATE.update_observed_activity(metric_source="controller")

    def stop_all(self):
        self.monitor_stop.set()
        for key in list(self.pids):
            self.stop_service(key)

    def apply_dashboard_config(self, previous, config):
        if config["natural_network_activity"]:
            if not self.is_running("natural_activity"):
                state_api_url = shlex.quote(config["state_api_url"])
                self.start_service(
                    "natural_activity",
                    "hmi",
                    f"python3 natural_activity.py --state-api-url {state_api_url} --interval 0.1",
                )
            if not self.is_running("external_battery_activity"):
                self.start_service(
                    "external_battery_activity",
                    "state_api",
                    "python3 external_battery_activity.py --battery-url http://10.0.2.50:8081/api/status --interval 0.2 --control-every 10",
                )
        else:
            self.stop_service("natural_activity")
            self.stop_service("external_battery_activity")

        if config["attack_status"] == "running" and not self.is_running("ddos_attack"):
            self.start_service(
                "ddos_attack",
                "attacker",
                f"python3 attack_generator.py --profile bad_battery_control --target 10.0.2.50:8081 --rate {int(config['attack_connections_per_second'])} --duration {int(config['duration_seconds'])} --wait {int(config['wait_seconds'])}",
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





