# NTADS: Network Traffic Anomaly Detection System (Colab-friendly)
# Features:
# - PCAP parsing with Scapy
# - Flow & per-second features
# - Rule-based detection (SYN flood, Port scan, DNS anomalies, DDoS bursts)
# - ML-based detection (Isolation Forest)
# - Visualization & alerting
# - Input/Output for Colab (upload) and local (path/CLI)
# Notes:
# - Live capture requires local admin/root; not supported on Colab

import sys, os, io, json, math, time, socket, statistics
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional

# ---------- Dependency check/install ----------
def _ensure(package, import_name=None, pip_name=None):
    import importlib
    try:
        return importlib.import_module(import_name or package)
    except ImportError:
        pip_pkg = pip_name or package
        print(f"Installing {pip_pkg} ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pip_pkg])
        return importlib.import_module(import_name or package)

np = _ensure("numpy")
pd = _ensure("pandas")
plt = _ensure("matplotlib", "matplotlib.pyplot")
sk = _ensure("sklearn", "sklearn")
requests = _ensure("requests")
scapy_all = _ensure("scapy", "scapy.all", "scapy==2.5.0")

from sklearn.ensemble import IsolationForest
from scapy.all import PcapReader, rdpcap, TCP, UDP, IP, IPv6, DNS, DNSQR, Raw

# Detect Colab
def _in_colab():
    try:
        import google.colab  # noqa
        return True
    except Exception:
        return False

# Optional Colab file upload
def _colab_upload():
    if not _in_colab():
        return {}
    from google.colab import files
    print("Upload a .pcap file to analyze.")
    uploaded = files.upload()
    return uploaded

# ---------- Configuration ----------
@dataclass
class RuleConfig:
    # Time windows (seconds)
    syn_window: int = 10
    scan_window: int = 60
    ddos_window: int = 10
    # Thresholds
    syn_flood_syns: int = 1000            # > this many SYNs from one src in syn_window
    port_scan_unique_ports: int = 100     # > this many unique dst ports from one src in scan_window
    ddos_pps_dest: int = 2000             # > packets per second to one dest IP
    dns_long_label: int = 30              # label length considered long
    dns_entropy_thresh: float = 3.5       # entropy per label considered suspicious
    dns_susp_queries: int = 20            # suspicious DNS queries per src within scan_window

@dataclass
class MLConfig:
    contamination: float = 0.02           # expected anomaly fraction
    random_state: int = 42
    max_samples: str = "auto"
    n_estimators: int = 200

@dataclass
class RunConfig:
    pcap_path: Optional[str] = None
    live_capture: bool = False            # local only, requires admin/root
    iface: Optional[str] = None
    max_packets: Optional[int] = None     # cap packets for quick tests
    save_outputs: bool = True
    webhook_url: Optional[str] = None     # optional alert webhook
    show_plot: bool = True

# ---------- Utilities ----------
def human_time(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

def label_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    cnt = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in cnt.values())

def ip_of(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst, "IPv4"
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst, "IPv6"
    return None, None, "OTHER"

def ports_proto(pkt):
    if TCP in pkt:
        return pkt[TCP].sport, pkt[TCP].dport, "TCP", pkt[TCP].flags
    if UDP in pkt:
        return pkt[UDP].sport, pkt[UDP].dport, "UDP", None
    return None, None, "OTHER", None

# ---------- Packet loading ----------
def load_packets_from_pcap(path: str, max_packets: Optional[int] = None):
    packets = []
    count = 0
    with PcapReader(path) as pcr:
        for pkt in pcr:
            packets.append(pkt)
            count += 1
            if max_packets and count >= max_packets:
                break
    return packets

def sniff_live(iface: Optional[str] = None, count: Optional[int] = None, timeout: Optional[int] = None):
    # Local only (requires privileges)
    from scapy.all import sniff
    return sniff(iface=iface, count=count, timeout=timeout)

# ---------- Feature extraction ----------
def extract_features(packets: List) -> Tuple[pd.DataFrame, pd.DataFrame, Dict]:
    # Per-packet records for per-second stats
    pkt_rows = []
    # Flow table: key=(src,dst,sport,dport,proto)
    flows: Dict[Tuple, Dict] = {}
    # Rule helper structures
    syn_events: List[Tuple[float, str]] = []       # (time, src)
    scan_events: Dict[str, List[int]] = {}         # src -> list of dst ports per time bin
    dns_queries: List[Dict] = []                   # DNS info
    dest_pps: Dict[str, Dict[int, int]] = {}       # dest -> time_bin -> count

    if not packets:
        return pd.DataFrame(), pd.DataFrame(), {"flows": {}, "dns": []}

    t0 = float(packets[0].time)
    for pkt in packets:
        try:
            ts = float(pkt.time)
            ip_src, ip_dst, ipver = ip_of(pkt)
            sport, dport, proto, flags = ports_proto(pkt)
            length = len(bytes(pkt)) if pkt else 0
            sec_bin = int(ts - t0)

            # Packet row for per-second summaries
            pkt_rows.append({
                "ts": ts, "rel_s": sec_bin, "src": ip_src, "dst": ip_dst,
                "proto": proto, "bytes": length
            })

            # Flow key
            key = (ip_src, ip_dst, sport, dport, proto)
            if key not in flows:
                flows[key] = {
                    "first_ts": ts, "last_ts": ts, "pkts": 0, "bytes": 0,
                    "sizes": [], "iat": [], "last_pkt_ts": None,
                    "syn": 0, "ack": 0, "fin": 0, "rst": 0,
                    "src": ip_src, "dst": ip_dst, "sport": sport, "dport": dport, "proto": proto
                }
            f = flows[key]
            f["pkts"] += 1
            f["bytes"] += length
            f["sizes"].append(length)
            if f["last_pkt_ts"] is not None:
                f["iat"].append(ts - f["last_pkt_ts"])
            f["last_pkt_ts"] = ts
            f["last_ts"] = ts

            # TCP flag counters and SYN events
            if proto == "TCP" and flags is not None:
                # Flags can be int or Flag object; normalize to int bits
                try:
                    val = int(flags)
                except Exception:
                    val = getattr(flags, "value", 0)
                # TCP flag bit positions: FIN=0x01, SYN=0x02, RST=0x04, ACK=0x10
                if val & 0x02:
                    f["syn"] += 1
                    if ip_src:
                        syn_events.append((ts, ip_src))
                if val & 0x10:
                    f["ack"] += 1
                if val & 0x01:
                    f["fin"] += 1
                if val & 0x04:
                    f["rst"] += 1

            # Port scan helper
            if proto in ("TCP", "UDP") and ip_src and dport is not None:
                scan_events.setdefault(ip_src, {}).setdefault(sec_bin, set()).add(int(dport))

            # DDoS dest PPS
            if ip_dst:
                dest_pps.setdefault(ip_dst, {}).setdefault(sec_bin, 0)
                dest_pps[ip_dst][sec_bin] += 1

            # DNS parse
            if DNS in pkt and pkt[DNS].qd is not None:
                # Handle multiple queries if present
                q = pkt[DNS].qd
                names = []
                if isinstance(q, DNSQR):
                    names = [q.qname.decode(errors="ignore").rstrip(".")]
                else:
                    # Rare: multiple QDs
                    try:
                        i = 0
                        while True:
                            qd = pkt[DNS].qd[i]
                            names.append(qd.qname.decode(errors="ignore").rstrip("."))
                            i += 1
                    except Exception:
                        pass
                for qname in names:
                    labels = qname.split(".")
                    long_labels = [lab for lab in labels if len(lab) >= 1]
                    entropies = [label_entropy(lab.lower()) for lab in long_labels]
                    dns_queries.append({
                        "ts": ts, "rel_s": sec_bin, "src": ip_src, "dst": ip_dst,
                        "qname": qname, "max_label_len": max([0] + [len(l) for l in labels]),
                        "avg_label_entropy": float(np.mean(entropies)) if entropies else 0.0
                    })
        except Exception:
            # Skip malformed packet gracefully
            continue

    # Build flow dataframe
    flow_rows = []
    for key, f in flows.items():
        dur = max(1e-6, f["last_ts"] - f["first_ts"])
        pps = f["pkts"] / dur
        bps = f["bytes"] / dur
        mean_size = float(np.mean(f["sizes"])) if f["sizes"] else 0.0
        std_size = float(np.std(f["sizes"])) if f["sizes"] else 0.0
        iat_mean = float(np.mean(f["iat"])) if f["iat"] else 0.0
        iat_std = float(np.std(f["iat"])) if f["iat"] else 0.0
        flow_rows.append({
            "src": f["src"], "dst": f["dst"], "sport": f["sport"], "dport": f["dport"], "proto": f["proto"],
            "first_ts": f["first_ts"], "last_ts": f["last_ts"], "duration_s": dur,
            "pkts": f["pkts"], "bytes": f["bytes"], "pps": pps, "bps": bps,
            "mean_size": mean_size, "std_size": std_size, "iat_mean": iat_mean, "iat_std": iat_std,
            "syn": f["syn"], "ack": f["ack"], "fin": f["fin"], "rst": f["rst"],
            "syn_ratio": f["syn"]/max(1, f["pkts"]), "ack_ratio": f["ack"]/max(1, f["pkts"])
        })
    df_flows = pd.DataFrame(flow_rows)
    df_pkts = pd.DataFrame(pkt_rows)
    df_dns = pd.DataFrame(dns_queries)
    return df_flows, df_pkts, {"flows": flows, "dns": dns_queries, "dest_pps": dest_pps,
                                "syn_events": syn_events, "scan_events": scan_events}

# ---------- Rule-based detectors ----------
def detect_syn_flood(syn_events: List[Tuple[float, str]], t0: float, cfg: RuleConfig):
    # Count SYNs per src per window
    alerts = []
    # Sort by time
    syn_events = sorted(syn_events, key=lambda x: x[0])
    # Sliding window using two pointers
    j = 0
    for i in range(len(syn_events)):
        t_i, src_i = syn_events[i]
        # Move j to maintain window
        while j < i and syn_events[j][0] < t_i - cfg.syn_window:
            j += 1
        # Count per src in window
        window = syn_events[j:i+1]
        counts = {}
        for t, s in window:
            counts[s] = counts.get(s, 0) + 1
        for s, c in counts.items():
            if c > cfg.syn_flood_syns:
                alerts.append({
                    "type": "SYN_FLOOD",
                    "src": s,
                    "count": c,
                    "window_s": cfg.syn_window,
                    "time": human_time(t_i),
                    "severity": "high"
                })
    # Deduplicate by src & time bucket
    dedup = {}
    out = []
    for a in alerts:
        key = (a["type"], a["src"], a["time"])
        if key not in dedup:
            dedup[key] = True
            out.append(a)
    return out

def detect_port_scan(scan_events: Dict[str, Dict[int, set]], cfg: RuleConfig):
    alerts = []
    for src, bins in scan_events.items():
        # For each rolling scan_window, count unique ports
        # Approximate by summing unique ports across bins inside the window
        if not bins:
            continue
        max_bin = max(bins.keys())
        for start in range(0, max_bin + 1, cfg.scan_window):
            window_ports = set()
            for b in range(start, start + cfg.scan_window):
                if b in bins:
                    window_ports |= bins[b]
            if len(window_ports) > cfg.port_scan_unique_ports:
                alerts.append({
                    "type": "PORT_SCAN",
                    "src": src,
                    "unique_ports": len(window_ports),
                    "window_s": cfg.scan_window,
                    "severity": "medium"
                })
    return alerts

def detect_ddos(dest_pps: Dict[str, Dict[int, int]], cfg: RuleConfig):
    alerts = []
    for dst, bins in dest_pps.items():
        for sec_bin, count in bins.items():
            if count > cfg.ddos_pps_dest:
                alerts.append({
                    "type": "DDOS_PPS",
                    "dst": dst,
                    "pps": count,
                    "window_s": 1,
                    "severity": "high"
                })
    return alerts

def detect_dns_anomalies(df_dns: pd.DataFrame, cfg: RuleConfig):
    alerts = []
    if df_dns is None or df_dns.empty:
        return alerts
    # Suspicious if long label or high entropy labels accumulate per source in window
    # Aggregate over scan_window
    df = df_dns.copy()
    if "rel_s" not in df:
        return alerts
    df["susp"] = (df["max_label_len"] >= cfg.dns_long_label) | (df["avg_label_entropy"] >= cfg.dns_entropy_thresh)
    if not df["susp"].any():
        return alerts
    # Count suspicious queries per src within windows
    for src, grp in df[df["susp"]].groupby("src"):
        if src is None:
            continue
        for start in range(0, int(grp["rel_s"].max()) + 1, cfg.scan_window):
            count = grp[(grp["rel_s"] >= start) & (grp["rel_s"] < start + cfg.scan_window)].shape[0]
            if count > cfg.dns_susp_queries:
                alerts.append({
                    "type": "DNS_EXFIL_SUSPECT",
                    "src": src,
                    "susp_queries": int(count),
                    "window_s": cfg.scan_window,
                    "severity": "medium"
                })
    return alerts

# ---------- ML-based anomaly detection ----------
def prepare_ml_features(df_flows: pd.DataFrame) -> pd.DataFrame:
    if df_flows is None or df_flows.empty:
        return pd.DataFrame()
    df = df_flows.copy()
    # Encode protocol
    for p in ["TCP", "UDP", "OTHER"]:
        df[f"proto_{p}"] = (df["proto"] == p).astype(int)
    # Replace NaN/inf
    for col in ["pps","bps","mean_size","std_size","iat_mean","iat_std","syn_ratio","ack_ratio",
                "pkts","bytes","duration_s","syn","ack","fin","rst","proto_TCP","proto_UDP","proto_OTHER"]:
        if col not in df.columns:
            df[col] = 0.0
        df[col] = df[col].replace([np.inf, -np.inf], 0).fillna(0)
    cols = ["pps","bps","mean_size","std_size","iat_mean","iat_std","syn_ratio","ack_ratio",
            "pkts","bytes","duration_s","syn","ack","fin","rst","proto_TCP","proto_UDP","proto_OTHER"]
    return df[cols]

def run_isolation_forest(X: pd.DataFrame, mlcfg: MLConfig):
    if X is None or X.empty:
        return None, None, None
    iso = IsolationForest(
        contamination=mlcfg.contamination,
        random_state=mlcfg.random_state,
        max_samples=mlcfg.max_samples,
        n_estimators=mlcfg.n_estimators,
        n_jobs=-1
    )
    iso.fit(X)
    scores = iso.decision_function(X)  # higher is less anomalous
    preds = iso.predict(X)             # -1 anomaly, 1 normal
    return iso, scores, preds

# ---------- Alerting ----------
def send_webhook(url: str, message: dict):
    if not url:
        return False
    try:
        resp = requests.post(url, json=message, timeout=5)
        return resp.status_code in (200, 201, 204)
    except Exception:
        return False

# ---------- Visualization ----------
def plot_time_series(df_pkts: pd.DataFrame, anomalies_time_bins: Optional[List[int]] = None, title: str = "Traffic PPS"):
    if df_pkts is None or df_pkts.empty:
        print("No packets to plot.")
        return
    grp = df_pkts.groupby("rel_s")["bytes"].count().rename("pps").reset_index()
    plt.figure(figsize=(10,4))
    plt.plot(grp["rel_s"], grp["pps"], label="Packets/sec", color="steelblue")
    if anomalies_time_bins:
        y = []
        x = []
        for b in anomalies_time_bins:
            if b in set(grp["rel_s"].values):
                x.append(b)
                y.append(int(grp.loc[grp["rel_s"] == b, "pps"]))
        if x:
            plt.scatter(x, y, color="red", label="Anomaly windows", zorder=3)
    plt.title(title)
    plt.xlabel("Seconds since start")
    plt.ylabel("Packets per second")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.show()

# ---------- Orchestration ----------
def run_ntads(run: RunConfig = RunConfig(), rules: RuleConfig = RuleConfig(), mlcfg: MLConfig = MLConfig()):
    # Input handling
    uploaded_name = None
    if _in_colab() and not run.pcap_path and not run.live_capture:
        uploaded = _colab_upload()
        if not uploaded:
            print("No file uploaded.")
            return None
        # Save uploaded to disk
        uploaded_name = next(iter(uploaded.keys()))
        with open(uploaded_name, "wb") as f:
            f.write(uploaded[uploaded_name])
        run.pcap_path = uploaded_name

    if run.live_capture:
        if _in_colab():
            print("Live capture is not available on Colab. Use a PCAP file instead.")
            return None
        print("Sniffing live traffic... (press Ctrl+C to stop)")
        packets = sniff_live(iface=run.iface, count=run.max_packets)
    else:
        if not run.pcap_path or not os.path.exists(run.pcap_path):
            print(f"PCAP not found: {run.pcap_path}")
            return None
        print(f"Loading PCAP: {run.pcap_path}")
        packets = load_packets_from_pcap(run.pcap_path, max_packets=run.max_packets)
        print(f"Loaded {len(packets)} packets.")

    if not packets:
        print("No packets to analyze.")
        return None

    # Feature extraction
    df_flows, df_pkts, aux = extract_features(packets)
    print(f"Extracted {len(df_flows)} flows and {len(df_pkts)} packet records.")

    # Rule-based detections
    t0 = float(packets[0].time)
    syn_alerts = detect_syn_flood(aux["syn_events"], t0, rules)
    scan_alerts = detect_port_scan(aux["scan_events"], rules)
    ddos_alerts = detect_ddos(aux["dest_pps"], rules)
    df_dns = pd.DataFrame(aux.get("dns", []))
    dns_alerts = detect_dns_anomalies(df_dns, rules)
    rule_alerts = syn_alerts + scan_alerts + ddos_alerts + dns_alerts

    # ML detections
    X = prepare_ml_features(df_flows)
    iso, scores, preds = run_isolation_forest(X, mlcfg)
    if preds is not None:
        df_flows = df_flows.copy()
        df_flows["if_score"] = scores
        df_flows["if_pred"] = preds
        df_anom = df_flows[df_flows["if_pred"] == -1].copy()
    else:
        df_anom = pd.DataFrame()

    # Map anomalies to time bins for plotting
    anomalies_bins = []
    if not df_flows.empty:
        # Approximate anomaly window by first_ts relative bin
        if "first_ts" in df_flows.columns:
            rel_bins = ((df_flows["first_ts"] - df_flows["first_ts"].min()).fillna(0)).astype(float)
            anomalies_bins = list(set((rel_bins[df_flows.get("if_pred", 1) == -1] - rel_bins.min()).astype(int).tolist()))
        else:
            anomalies_bins = []

    # Output
    if run.save_outputs:
        df_flows.to_csv("flows.csv", index=False)
        if not df_anom.empty:
            df_anom.to_csv("anomalies.csv", index=False)
        with open("alerts.json", "w") as f:
            json.dump(rule_alerts, f, indent=2)
        print("Saved outputs: flows.csv, anomalies.csv (if any), alerts.json")

    # Alerting via webhook (optional)
    if run.webhook_url and rule_alerts:
        for a in rule_alerts[:5]:  # limit
            ok = send_webhook(run.webhook_url, a)
            if ok:
                print(f"Webhook sent: {a['type']} -> OK")
            else:
                print(f"Webhook failed: {a['type']}")

    # Visualization
    if run.show_plot:
        # Build list of anomaly bins from rules too (dest PPS bins)
        rbins = []
        for a in ddos_alerts:
            # a is per-second PPS on dest; approximate by window bin if available
            # We don't store bin explicitly; skip for simplicity
            pass
        plot_time_series(df_pkts, anomalies_time_bins=anomalies_bins, title="Packets/sec with ML anomalies")

    # Summary
    print("\n=== Summary ===")
    print(f"- Packets: {len(df_pkts)}")
    print(f"- Flows: {len(df_flows)}")
    print(f"- Rule alerts: {len(rule_alerts)} "
          f"(SYN:{len(syn_alerts)}, Scan:{len(scan_alerts)}, DNS:{len(dns_alerts)}, DDoS:{len(ddos_alerts)})")
    print(f"- ML anomalies (IsolationForest): {0 if df_anom.empty else len(df_anom)}")
    if uploaded_name:
        print(f"- Analyzed uploaded file: {uploaded_name}")

    result = {
        "flows": df_flows,
        "anomalies_ml": df_anom,
        "rule_alerts": rule_alerts,
        "packets_df": df_pkts,
        "dns_df": df_dns
    }
    return result

# ---------- Convenient entry points ----------
def run_with_path(pcap_path: str,
                  save_outputs: bool = True,
                  show_plot: bool = True,
                  contamination: float = 0.02,
                  max_packets: Optional[int] = None):
    run = RunConfig(pcap_path=pcap_path, save_outputs=save_outputs, show_plot=show_plot, max_packets=max_packets)
    mlcfg = MLConfig(contamination=contamination)
    return run_ntads(run=run, mlcfg=mlcfg)

# Auto-run if in Colab (upload) or show how to use via CLI
if __name__ == "__main__":
    if _in_colab():
        run_ntads()
    elif len(sys.argv) >= 2:
        path = sys.argv[1]
        contamination = float(sys.argv[2]) if len(sys.argv) >= 3 else 0.02
        run_with_path(path, save_outputs=True, show_plot=True, contamination=contamination)
    else:
        print("Usage: python ntads.py <path_to.pcap> [contamination]")