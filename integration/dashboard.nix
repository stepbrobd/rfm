{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-dashboard";

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  nodes = {
    inherit (common) machine2;

    # prometheus scrapes the agent every second, and the agent evicts a flow
    # after five idle seconds
    machine1 = {
      imports = [ common.machine1 ];

      services.prometheus = {
        enable = true;
        globalConfig.scrape_interval = "1s";
        scrapeConfigs = [
          {
            job_name = "rfm";
            static_configs = [ { targets = [ "[::1]:9669" ]; } ];
          }
        ];
      };
    };
  };

  testScript = common.helpers + ''
    import json
    import re
    import shlex

    with open("${../grafana/dashboard.json}") as f:
      dashboard = json.load(f)
    panels = {panel["title"]: panel for panel in dashboard["panels"]}

    def prometheus(path: str, *params: str) -> list:
      # no -f, a rejected query answers with the reason in the body
      args = " ".join(f"--data-urlencode {shlex.quote(param)}" for param in params)
      reply = json.loads(machine1.succeed(f"curl -sG http://localhost:9090/api/v1/{path} {args}"))
      assert reply["status"] == "success", f"{path} {params}: {reply}"
      return reply["data"]["result"] if path == "query" else reply["data"]

    def interpolate(expr: str, direction: str) -> str:
      # what grafana fills in, a range that covers the whole test, every
      # interface and one direction
      values = {"__range": "10m", "__rate_interval": "4s", "ifname": ".*", "direction": direction}
      return re.sub(r"\$\{?(\w+)\}?", lambda m: values[m.group(1)], expr)

    def label_values(title: str, label: str, direction: str) -> set[str]:
      return {
        series["metric"].get(label, "")
        for target in panels[title]["targets"]
        for series in prometheus("query", "query=" + interpolate(target["expr"], direction))
      }

    def asn_of(ip: str) -> str:
      return machine1.succeed(
        "mmdblookup --file \"$(cat /etc/rfm-test-asn-db)\" "
        f"--ip {ip} autonomous_system_number "
        "| grep -Eo '[0-9]+ <uint32>' | cut -d' ' -f1"
      ).strip()

    start_all()
    machine1.wait_for_unit("rfm.service")
    machine1.wait_for_unit("prometheus.service")
    machine1.wait_for_open_port(9090)
    machine2.wait_for_unit("multi-user.target")
    machine1.wait_until_succeeds(
      "curl -sfG http://localhost:9090/api/v1/query --data-urlencode 'query=up{job=\"rfm\"} == 1' | grep -q value"
    )

    # a public source and destination routed through machine2, so every
    # label the rankings group by is set
    machine1.succeed("ip addr add 1.1.1.1/32 dev lo")
    machine1.succeed("ip route add 8.8.8.0/24 via 192.168.1.2")
    src_asn = asn_of("1.1.1.1")
    dst_asn = asn_of("8.8.8.8")

    # echo requests over several scrapes, nothing answers them
    machine1.succeed("ping -c 50 -i 0.1 -W 1 -I 1.1.1.1 8.8.8.8 || true")

    # the flow leaves the table after the eviction timeout, which the
    # rankings over the dashboard range must not notice
    machine1.wait_until_succeeds(
      f"! curl -sf http://localhost:9669/metrics | grep -q 'rfm_flow_bytes{{.*dst_asn=\"{dst_asn}\"'"
    )

    # every query of the dashboard is valid and finds the series it names
    for panel in dashboard["panels"]:
      for target in panel.get("targets", []):
        expr = interpolate(target["expr"], "egress")
        assert prometheus("query", "query=" + expr), f"{panel['title']}: no data for {expr}"

    for variable in dashboard["templating"]["list"]:
      if variable["type"] == "query":
        match = re.fullmatch(r"label_values\((\w+), *(\w+)\)", variable["definition"])
        assert match, f"variable {variable['name']}: unexpected query {variable['definition']}"
        metric, label = match.groups()
        found = set(prometheus(f"label/{label}/values", f"match[]={metric}"))
        assert {"eth1", "lo"} <= found, f"variable {variable['name']}: {found}"

    # the rankings count the echo requests over the whole range, and only in
    # the direction they took
    for title, label, asn in [
      ("Top Source ASNs by Traffic", "src_asn", src_asn),
      ("Top Destination ASNs by Traffic", "dst_asn", dst_asn),
      ("ASN Pair Traffic", "src_asn", src_asn),
      ("ASN Pair Traffic", "dst_asn", dst_asn),
    ]:
      assert asn in label_values(title, label, "egress"), f"{title}: {label} {asn} missing from egress"
      assert asn not in label_values(title, label, "ingress"), f"{title}: {label} {asn} counted as ingress"

    for title, label in [
      ("Top Source Cities by Traffic", "src_city"),
      ("Top Destination Cities by Traffic", "dst_city"),
      ("City-to-City Traffic", "src_city"),
      ("City-to-City Traffic", "dst_city"),
    ]:
      assert label_values(title, label, "egress") - {""}, f"{title}: no {label} in egress"
      assert not label_values(title, label, "ingress") - {""}, f"{title}: {label} counted as ingress"

    assert "1" in label_values("Traffic by Protocol", "proto", "egress"), "Traffic by Protocol: no icmp in egress"
  '';
}
