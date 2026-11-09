#!/usr/bin/env python3
"""netdiag - find out where packet loss / latency spikes on a macOS connection come from.

Usage:
  ./netdiag.py run                          # live dashboard, Ctrl+C to stop and get the report
  ./netdiag.py run -i 0.02                  # probe every 20 ms (default 50 ms)
  ./netdiag.py run --link ethernet          # skip connection auto-detection
  ./netdiag.py run --ont 192.168.100.1      # setup with a separate ONT that has an IP
  ./netdiag.py summarize                    # compare saved runs side by side
  ./netdiag.py analyze ping-log.txt         # analyze saved `ping` output

Works on any macOS machine; everything is detected automatically. The default
assumes the ISP's box is modem and router in one (fiber box with built-in router,
cable or DSL modem-router): hop 1 is that box, hop 2 the ISP's first router, so
the segment between them is your internet line. With a separate ONT/modem that
has its own IP, pass it via --ont.

`run` traces the first hops towards 1.1.1.1, then sends one probe to the home
router, each traced hop and two internet hosts at the same moment. Where the
loss rate steps up and stays up for everything behind it is where packets get
lost:

  home-router lost                     -> your Wi-Fi / LAN
  home-router ok, hop 2 + rest lost    -> your internet line (box ↔ ISP)
  hop N ok, hop N+1 + rest lost        -> inside the ISP's network
  only an intermediate hop lost        -> that hop rate-limits ICMP (not real loss)
"""
import argparse
import bisect
import concurrent.futures
import contextlib
import errno
import glob
import json
import math
import os
import re
import select
import signal
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import termios
import threading
import time
import tty as ttymode
from collections import Counter, deque

REPLY_RE = re.compile(r"icmp_seq=(\d+).*?time=([\d.]+) ms")
TIMEOUT_RE = re.compile(r"Request timeout for icmp_seq (\d+)")
# kernel receive timestamps (macOS values; Python doesn't export them)
SO_TIMESTAMP, SCM_TIMESTAMP = getattr(socket, "SO_TIMESTAMP", 0x400), getattr(socket, "SCM_TIMESTAMP", 2)

# Path order of targets. Traced hop N gets rank RANK_HOP + N.
RANK_ROUTER, RANK_ONT, RANK_HOP, RANK_DEST = 0, 1, 10, 100


# ---------------------------------------------------------------- parsing

def parse_ping_lines(lines):
    """Return {seq: rtt_ms or None} from macOS/Linux ping output."""
    samples = {}
    for line in lines:
        m = REPLY_RE.search(line)
        if m:
            samples[int(m.group(1))] = float(m.group(2))
            continue
        m = TIMEOUT_RE.search(line)
        if m:
            samples.setdefault(int(m.group(1)), None)
    if samples:
        # Linux ping doesn't print timeouts; treat missing seqs as lost.
        for s in range(min(samples), max(samples) + 1):
            samples.setdefault(s, None)
    return dict(sorted(samples.items()))


# ---------------------------------------------------------------- statistics

def pct(sorted_vals, p):
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def find_modes(rtts, bin_ms=0.5):
    """Find latency clusters in a histogram. Returns [(center_ms, share)]."""
    if len(rtts) < 30:
        return []
    bins = Counter(int(r / bin_ms) for r in rtts)
    lo, hi = min(bins), max(bins)
    hist = [bins.get(b, 0) for b in range(lo, hi + 1)]
    # light smoothing so a single noisy bin doesn't create a fake peak
    sm = [sum(hist[max(0, i - 1):i + 2]) / len(hist[max(0, i - 1):i + 2]) for i in range(len(hist))]
    peaks = [i for i in range(len(sm))
             if sm[i] >= max(sm[max(0, i - 2):i + 3]) and hist[i] >= 0.05 * len(rtts)]
    # merge peaks closer than 2 ms
    merged = []
    for p in peaks:
        if merged and (p - merged[-1]) * bin_ms < 2:
            if sm[p] > sm[merged[-1]]:
                merged[-1] = p
        else:
            merged.append(p)
    if len(merged) < 2:
        return [(statistics.median(rtts), 1.0)]
    centers = [(lo + p + 0.5) * bin_ms for p in merged]
    counts = Counter(min(range(len(centers)), key=lambda c: abs(r - centers[c])) for r in rtts)
    return [(centers[i], counts[i] / len(rtts)) for i in range(len(centers))]


def analyze_series(samples, interval_s=1.0):
    seqs = list(samples)
    rtts = [v for v in samples.values() if v is not None]
    lost = [s for s, v in samples.items() if v is None]
    n = len(seqs)
    r = {"sent": n, "recv": len(rtts), "lost": len(lost),
         "loss_pct": 100 * len(lost) / n if n else 0.0, "lost_seqs": lost}
    if not rtts:
        return r
    srt = sorted(rtts)
    med = statistics.median(rtts)
    mad = statistics.median(abs(x - med) for x in rtts) or 0.1
    r.update(min=srt[0], p50=med, p90=pct(srt, 90), p99=pct(srt, 99), max=srt[-1],
             mean=statistics.mean(rtts), stdev=statistics.pstdev(rtts))
    vals = list(samples.values())
    diffs = [abs(b - a) for a, b in zip(vals, vals[1:]) if a is not None and b is not None]
    r["jitter"] = statistics.mean(diffs) if diffs else 0.0

    # burst structure of losses
    bursts, cur = [], 0
    for v in vals:
        if v is None:
            cur += 1
        elif cur:
            bursts.append(cur)
            cur = 0
    if cur:
        bursts.append(cur)
    r["bursts"] = bursts

    # spikes: way above the typical spread
    thresh = max(med + 6 * mad, med * 1.8)
    r["spike_thresh"] = thresh
    r["spikes"] = [s for s, v in samples.items() if v is not None and v > thresh]

    # does latency get worse right before a loss? (sign of airtime congestion / retries)
    pre = [samples[s - k] for s in lost for k in (1, 2, 3) if samples.get(s - k) is not None]
    r["pre_loss_median"] = statistics.median(pre) if pre else None

    # periodicity of loss events (count a burst once)
    starts = [s for s in lost if samples.get(s - 1) is not None]
    if len(starts) >= 4:
        gaps = [(b - a) * interval_s for a, b in zip(starts, starts[1:])]
        r["loss_gap_median_s"] = statistics.median(gaps)
        r["loss_gap_cv"] = statistics.pstdev(gaps) / statistics.mean(gaps)

    r["modes"] = find_modes(rtts)
    r["interval"] = interval_s
    return r


# ---------------------------------------------------------------- reporting

def bar(share, width=30):
    """Filled part plus a light track up to 100%, framed so the full width is visible."""
    n = max(1, round(share * width))
    return "▕" + "█" * n + "░" * (width - n) + "▏"


def fmt_dur(s):
    return f"{s * 1000:.0f} ms" if s < 1 else f"{s:.1f} s"


def print_series(name, r):
    print(f"\n── {name} " + "─" * max(0, 60 - len(name)))
    if not r["sent"]:
        print("  no data")
        return
    print(f"  packets   {r['sent']} sent, {r['recv']} received, "
          f"{r['lost']} lost ({r['loss_pct']:.2f}%)")
    if "p50" not in r:
        return
    print(f"  latency   min {r['min']:.1f} / p50 {r['p50']:.1f} / p90 {r['p90']:.1f} / "
          f"p99 {r['p99']:.1f} / max {r['max']:.1f} ms")
    print(f"  jitter    {r['jitter']:.2f} ms (mean change between consecutive replies)")
    if r["bursts"]:
        c = Counter(r["bursts"])
        iv = r["interval"]
        desc = ", ".join(f"{c[k]}× {k} in a row" + (f" ({fmt_dur(k * iv)})" if iv < 1 else "")
                         for k in sorted(c)[:6])
        if len(c) > 6:
            desc += f", … up to {max(c)}"
        print(f"  loss      {desc}")
        if r.get("pre_loss_median"):
            print(f"            median RTT in the 3 probes before a loss: {r['pre_loss_median']:.1f} ms "
                  f"(overall median {r['p50']:.1f} ms)")
        if "loss_gap_median_s" in r:
            print(f"            time between losses: median {r['loss_gap_median_s']:.0f}s, "
                  f"variation {r['loss_gap_cv']:.2f} (low = periodic)")
    print(f"  spikes    {len(r['spikes'])} replies above {r['spike_thresh']:.1f} ms")
    if len(r["modes"]) > 1:
        print("  latency clusters:")
        for c, share in r["modes"]:
            print(f"            ~{c:5.1f} ms  {share * 100:4.0f}%  {bar(share)}")


def loss_causes(link):
    if link == "wifi":
        return ("radio interference/contention, the Mac going off-channel (AWDL/AirDrop, "
                "background Wi-Fi scans), or loss further along the path")
    return "a congested or faulty link along the path (the hop table shows where it starts)"


def findings_for(r, label, link="wifi", loss=True, modes=True):
    """Heuristic interpretation of one series. Returns list of (severity, text)."""
    out = []
    if not r["sent"] or "p50" not in r:
        return out
    if loss and r["loss_pct"] >= 0.5:
        bursts = r["bursts"]
        # at sub-second intervals a "single" frame loss can span a few probes
        short = max(1, int(0.3 / r["interval"]))
        singles = sum(1 for b in bursts if b <= short) / len(bursts)
        if singles >= 0.8:
            out.append(("!", f"{label}: {r['loss_pct']:.1f}% loss, almost all short isolated losses. "
                        "Outages (disconnects, roaming, DHCP) cause long bursts; "
                        f"isolated losses point to individual packets getting lost: {loss_causes(link)}."))
        else:
            longest = max(bursts) * r["interval"]
            out.append(("!", f"{label}: {r['loss_pct']:.1f}% loss including outages up to "
                        f"{fmt_dur(longest)}: short outages (roaming, deauth, AP/modem "
                        "resets, DFS channel switch, fiber link flaps)."))
        if r.get("loss_gap_cv") is not None and r["loss_gap_cv"] < 0.35:
            out.append(("!", f"{label}: losses come at a fairly regular interval "
                        f"(~{r['loss_gap_median_s']:.0f}s). A regular pattern usually means a "
                        "scheduled job: background scans (Location Services, Wi-Fi menu open), "
                        "AWDL, or the router doing something on a timer."))
    if modes and len(r["modes"]) > 1:
        lo, hi = r["modes"][0][0], r["modes"][-1][0]
        out.append(("i", f"{label}: latency jumps between ~{lo:.0f} ms and ~{hi:.0f} ms "
                    f"(+{hi - lo:.1f} ms) instead of varying smoothly. A fixed step like that "
                    "usually comes from scheduling, not distance: Wi-Fi power-save wake-ups, "
                    "AWDL channel switching, or the access network (GPON/DOCSIS upstream "
                    "grant slots, two load-balanced paths). The hop where the step first "
                    "appears is where it comes from."))
    if modes and r["jitter"] > 5:   # TCP handshake timing is too uneven to judge jitter
        out.append(("!", f"{label}: high jitter ({r['jitter']:.1f} ms), bad for calls and gaming."))
    return out


def wifi_findings(samples):
    out = []
    if not samples:
        return out
    last = samples[-1]
    # rssi/noise of 0 means "not associated" (e.g. Wi-Fi off), not a reading
    samples = [s for s in samples if s.get("rssi", -1) != 0] or [samples[-1]]
    rssis = [s["rssi"] for s in samples if s.get("rssi")]
    snrs = [s["rssi"] - s["noise"] for s in samples if s.get("rssi") and s.get("noise")]
    rates = [s["rate"] for s in samples if s.get("rate")]
    chans = Counter(s.get("channel") for s in samples)

    print("\n── Wi-Fi " + "─" * 52)
    skipped = last.get("scan_skipped")
    if skipped:
        print(f"  channel   {last.get('channel', '?')}")
    else:
        print(f"  channel   {last.get('channel_raw')}  PHY {last.get('phy')}  MCS {last.get('mcs')}")
    if rssis:
        print(f"  signal    {min(rssis)} … {max(rssis)} dBm (median {statistics.median(rssis):.0f})"
              + (f", SNR median {statistics.median(snrs):.0f} dB" if snrs else ""))
    if rates:
        print(f"  tx rate   {min(rates):.0f} … {max(rates):.0f} Mbps")
    if skipped:
        print(f"  neighbor networks: not scanned ({skipped} lost no relevant packets)")
        out.append(("i", f"{skipped} lost no relevant packets, so Wi-Fi is ruled out as the cause "
                    "and the neighbor scan was skipped."))
    else:
        print(f"  same-channel networks nearby: {last.get('cochannel', '?')}  "
              f"(overlapping 5 GHz: {last.get('overlap', '?')})")
    print(f"  AWDL (AirDrop/Continuity interface): {'UP' if last.get('awdl_up') else 'down'}")

    if snrs:
        snr = statistics.median(snrs)
        if snr >= 30:
            out.append(("i", f"Wi-Fi signal is strong (SNR ~{snr:.0f} dB). Range or "
                        "distance is not your problem."))
        elif snr >= 20:
            out.append(("i", f"Wi-Fi SNR is OK (~{snr:.0f} dB) but not great; check for walls, "
                        "metal or a closed laptop lid in the way."))
        else:
            out.append(("!", f"Wi-Fi SNR is poor (~{snr:.0f} dB). Move closer or reposition the AP."))
    if rssis and max(rssis) - min(rssis) >= 12:
        out.append(("!", f"Signal swings by {max(rssis) - min(rssis)} dB during the test: "
                    "something moves through the path, or the AP's band steering moves you around."))
    if len(chans) > 1:
        out.append(("!", f"Channel changed during the test ({', '.join(map(str, chans))}): "
                    "the AP switched channel (DFS radar event or auto-channel) or you roamed."))
    ch = last.get("channel")
    if ch and 52 <= ch <= 144:
        out.append(("!", f"Channel {ch} is a DFS channel. The AP has to leave it whenever it "
                    "detects radar, which disconnects every client for a moment. Use 36-48 if bursts show up."))
    if last.get("cochannel"):
        out.append(("!", f"{last['cochannel']} other network(s) on your exact channel "
                    f"({last.get('channel_raw')}) and {last.get('overlap', 0)} more overlapping "
                    "your 80 MHz block. They share airtime with you, and their traffic causes "
                    "collisions and retries, which show up as single lost pings and latency steps. "
                    "If one of them is your own second AP/mesh node, that's expected; "
                    "otherwise move your AP to a free 80 MHz block."))
    if last.get("awdl_up") and skipped:
        out.append(("i", "AWDL (AirDrop/Handoff) is active. It didn't cause the loss here (the "
                    "home router lost nothing), but it can add periodic latency spikes: "
                    "`sudo ifconfig awdl0 down` turns it off until reboot."))
    elif last.get("awdl_up"):
        out.append(("!", "AWDL is active. macOS periodically switches the radio to the AWDL "
                    "channel for AirDrop/AirPlay/Handoff/Sidecar, which is a well-known cause of "
                    "periodic latency spikes and loss. Test: `sudo ifconfig awdl0 down` "
                    "(revert: `sudo ifconfig awdl0 up`, also reverts on reboot), then run again."))
    return out


def ethernet_findings(iface, before, after):
    out = []
    media = subprocess.run(["ifconfig", iface], capture_output=True, text=True).stdout
    m = re.search(r"media: (.*)", media)
    media = m.group(1) if m else "?"
    print("\n── Ethernet " + "─" * 49)
    print(f"  media     {media}")
    if before and after:
        d = {k: after[k] - before[k] for k in after}
        print(f"  counters  in-errors {d['ierrs']}, out-errors {d['oerrs']}, collisions {d['coll']} "
              f"(during the test)")
        if d["ierrs"] or d["oerrs"] or d["coll"]:
            out.append(("i", f"Interface errors on {iface} during the test (in {d['ierrs']}, out "
                        f"{d['oerrs']}, collisions {d['coll']}). Either a bad cable / connector / "
                        "adapter, or frames the adapter discards anyway (e.g. other VLANs). "
                        "Whether they line up with the losses is checked below."))
    if "half-duplex" in media:
        out.append(("!", "Link is half-duplex: a duplex mismatch causes loss under load. "
                    "Replace the cable or force full-duplex on the switch/router port."))
    if re.search(r"\b10+baseT\b", media) and "1000" not in media and "2500" not in media:
        out.append(("!", f"Link negotiated only {media}: usually a damaged cable (gigabit needs "
                    "all 4 wire pairs) or a cheap adapter/switch."))
    return out


def print_findings(findings):
    if not findings:
        print("\nNo obvious problems found.")
        return
    print("\n══ Findings " + "═" * 50)
    for sev, text in findings:
        mark = "⚠" if sev == "!" else "•"
        print(f"\n {mark} " + wrap(text, 74, "   "))


def wrap(text, width, indent):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    lines.append(cur)
    return ("\n" + indent).join(lines)


# ---------------------------------------------------------------- environment

def default_route():
    out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout
    m = re.search(r"gateway:\s*(\S+)", out)
    i = re.search(r"interface:\s*(\S+)", out)
    return (m.group(1) if m else None), (i.group(1) if i else None)


def hardware_ports():
    out = subprocess.run(["networksetup", "-listallhardwareports"], capture_output=True, text=True).stdout
    return dict((dev, port) for port, dev in re.findall(r"Hardware Port: (.+)\nDevice: (\S+)", out))


def detect_link(iface, forced):
    """Return 'wifi' or 'ethernet' for the interface carrying the default route."""
    if forced:
        return forced
    port = hardware_ports().get(iface, "")
    if "Wi-Fi" in port or "AirPort" in port:
        return "wifi"
    if port:
        # Wi-Fi is the only wireless port type; anything else listed (often named after
        # the adapter's chip, e.g. "AX88179B") is wired
        return "ethernet"
    if sys.stdin.isatty():
        print(f"Couldn't tell what kind of link {iface} ({port or 'unknown port'}) is.")
        while True:
            a = input("Are you on [w]i-fi or [e]thernet? ").strip().lower()
            if a[:1] in ("w", "e"):
                return "wifi" if a[0] == "w" else "ethernet"
    return "wifi"


def iface_counters(iface):
    out = subprocess.run(["netstat", "-I", iface], capture_output=True, text=True).stdout.splitlines()
    if len(out) < 2:
        return None
    hdr = out[0].split()
    row = out[1].split()
    try:
        # rows may lack the Address column; count from the end
        get = lambda name: int(row[len(row) - (len(hdr) - hdr.index(name))])
        return {"ierrs": get("Ierrs"), "oerrs": get("Oerrs"), "coll": get("Coll")}
    except (ValueError, IndexError):
        return None


def trace_hops(dest, max_hops):
    """traceroute to dest. Returns (raw output, [(hop number, ip)])."""
    out = subprocess.run(["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(max_hops), dest],
                         capture_output=True, text=True, timeout=60).stdout
    hops = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            hops.append((int(m.group(1)), m.group(2)))
    return out, hops


def trace_all(dests, max_hops=20):
    """Trace every destination in parallel. Returns {dest: (raw output, hops)}."""
    res = {}

    def one(d):
        res[d] = trace_hops(d, max_hops)

    threads = [threading.Thread(target=one, args=(d,)) for d in dests]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return res


def answers_echo(addrs):
    """Subset of addrs that answer normal pings (some routers only send TTL-exceeded)."""
    ok = set()

    def check(a):
        r = subprocess.run(["ping", "-n", "-c", "3", "-i", "0.2", "-t", "2", a],
                           capture_output=True, text=True)
        if " 0.0% packet loss" in r.stdout or re.search(r"[12] packets received", r.stdout):
            ok.add(a)

    threads = [threading.Thread(target=check, args=(a,)) for a in addrs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return ok


def open_tcp_port(addr, ports=(80, 443)):
    """First port that completes a TCP handshake (or refuses it), else None."""
    for port in ports:
        try:
            socket.create_connection((addr, port), timeout=1.5).close()
            return port
        except ConnectionRefusedError:
            return port
        except OSError:
            continue
    return None


def python_reaches(addr, timeout=1.0):
    """One ICMP echo from this process. Returns (ok, error text)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        s.settimeout(timeout)
        ident, payload = (os.getpid() + 77) & 0xFFFF, b"netdiag-preflight"
        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
        s.sendto(struct.pack("!BBHHH", 8, 0, icmp_checksum(hdr + payload), ident, 1) + payload,
                 (addr, 0))
        deadline = time.time() + timeout
        while time.time() < deadline:
            data, _ = s.recvfrom(2048)
            ihl = (data[0] & 0x0F) * 4
            if struct.unpack("!BBHHH", data[ihl:ihl + 8])[3] == ident:
                return True, ""
        return False, "no reply"
    except OSError as e:
        return False, e.strerror or str(e)


def check_local_network_access(targets):
    """macOS 15+ blocks apps without the Local Network permission from reaching devices on
    directly attached networks, while /sbin/ping still works. Detect that and say so."""
    local = [t for t in targets if not t.port and t.rank < RANK_DEST and on_link(t.addr)]
    if not local:
        return
    ping_ok = answers_echo([t.addr for t in local])
    blocked = [(t, err) for t in local if t.addr in ping_ok
               for ok, err in [python_reaches(t.addr)] if not ok]
    if not blocked:
        return
    app = os.environ.get("TERM_PROGRAM", "your terminal app").replace("Apple_Terminal", "Terminal")
    print(f"\n  ⚠ ping reaches {', '.join(t.addr for t, _ in blocked)}, but this program can't "
          f"({blocked[0][1]}).\n"
          f"    macOS is blocking local-network access for {app}. Allow it in System Settings →\n"
          f"    Privacy & Security → Local Network, then restart {app} and run again.\n"
          "    (Until then those hops show 100% loss and are left out of the analysis.)\n")


def physical_iface(iface):
    """The physical adapter under a VLAN interface (vlan0 → en9); others unchanged."""
    out = subprocess.run(["ifconfig", iface], capture_output=True, text=True).stdout
    m = re.search(r"parent interface: (\S+)", out)
    return m.group(1) if m else iface


def on_link(addr):
    """True if addr is reached directly (same cable/subnet), not via a gateway."""
    out = subprocess.run(["route", "-n", "get", addr], capture_output=True, text=True).stdout
    return "gateway:" not in out and "interface:" in out


def is_router_itself(addr):
    """True if addr answers at hop 1, i.e. it's an address of the router, not a device behind it."""
    out = subprocess.run(["traceroute", "-n", "-q", "1", "-w", "1", "-m", "1", addr],
                         capture_output=True, text=True, timeout=10).stdout
    return bool(re.search(rf"^\s*1\s+{re.escape(addr)}\s", out, re.M))


def wifi_snapshot(iface):
    snap = {"t": time.time()}
    try:
        raw = subprocess.run(["system_profiler", "SPAirPortDataType", "-json"],
                             capture_output=True, text=True, timeout=30).stdout
        ifs = json.loads(raw)["SPAirPortDataType"][0]["spairport_airport_interfaces"]
    except Exception as e:
        snap["error"] = str(e)
        return snap
    for i in ifs:
        if i.get("_name") != iface:
            continue
        cur = i.get("spairport_current_network_information", {})
        chan_raw = cur.get("spairport_network_channel", "")
        m = re.match(r"(\d+)\s*\((\w+),\s*(\d+)MHz\)", chan_raw)
        ch, band, width = (int(m.group(1)), m.group(2), int(m.group(3))) if m else (None, None, 20)
        sn = re.findall(r"-?\d+", cur.get("spairport_signal_noise", ""))
        snap.update(channel=ch, band=band, width=width, channel_raw=chan_raw,
                    phy=cur.get("spairport_network_phymode"), mcs=cur.get("spairport_network_mcs"),
                    rate=cur.get("spairport_network_rate"),
                    rssi=int(sn[0]) if sn else None, noise=int(sn[1]) if len(sn) > 1 else None)
        co = ov = 0
        my_block = block_of(ch, width) if ch and band == "5GHz" else None
        for n in i.get("spairport_airport_other_local_wireless_networks", []):
            m2 = re.match(r"(\d+)\s*\((\w+),\s*(\d+)MHz\)", n.get("spairport_network_channel", ""))
            if not m2 or m2.group(2) != band:
                continue
            nch, nw = int(m2.group(1)), int(m2.group(3))
            if nch == ch:
                co += 1
            elif my_block and block_of(nch, nw) & my_block:
                ov += 1
        snap.update(cochannel=co, overlap=ov)
    snap["awdl_up"] = awdl_up()
    return snap


# system_profiler triggers a Wi-Fi scan, which takes the radio off-channel and
# itself causes 50-150 ms spikes. During a run we sample through CoreWLAN instead,
# which only reads the current link state.
SAMPLER_SWIFT = r"""
import CoreWLAN
import Foundation
let every = Double(CommandLine.arguments[1])!
guard let i = CWWiFiClient.shared().interface() else { exit(1) }
while true {
  print("\(Date().timeIntervalSince1970) \(i.rssiValue()) \(i.noiseMeasurement()) \(i.transmitRate()) \(i.wlanChannel()?.channelNumber ?? -1)")
  fflush(stdout)
  Thread.sleep(forTimeInterval: every)
}
"""


def start_link_sampler(every, out_dir, samples):
    """Stream scan-free link stats into `samples`. Returns the Popen or None."""
    path = os.path.join(out_dir, "sampler.swift")
    with open(path, "w") as f:
        f.write(SAMPLER_SWIFT)
    try:
        proc = subprocess.Popen(["swift", path, str(every)], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except FileNotFoundError:
        return None

    def reader():
        for line in proc.stdout:
            p = line.split()
            if len(p) == 5:
                samples.append({"t": float(p[0]), "rssi": int(p[1]), "noise": int(p[2]),
                                "rate": float(p[3]), "channel": int(p[4])})

    threading.Thread(target=reader, daemon=True).start()
    return proc


def block_of(ch, width):
    """Set of 20 MHz 5 GHz channels covered by a channel of a given width."""
    span = max(1, width // 20)
    base = 36 if ch < 149 else 149
    start = base + ((ch - base) // (4 * span)) * 4 * span
    return set(range(start, start + 4 * span, 4))


def awdl_up():
    out = subprocess.run(["ifconfig", "awdl0"], capture_output=True, text=True).stdout
    return "status: active" in out or ("<UP" in out and "RUNNING" in out)


# ---------------------------------------------------------------- prober

def icmp_checksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class Target:
    def __init__(self, name, addr, rank, hop=None, port=None):
        self.name, self.addr, self.rank, self.hop = name, addr, rank, hop
        self.port = port       # None = ICMP echo, otherwise TCP connect to this port
        self.rtt = []          # index = round; float ms, None = lost, absent = pending
        self.late = 0          # replies that came after the timeout
        self.lost_at = 0       # wall time the last probe was declared lost (dashboard flash)


class Prober:
    """Probes every target once per round: ICMP echo over an unprivileged ICMP socket,
    or a TCP handshake for targets with a port (measures what real traffic sees, even
    where ICMP is deprioritized)."""

    def __init__(self, targets, interval, timeout=1.0):
        self.targets, self.interval, self.timeout = targets, interval, timeout
        # Each ICMP target gets its own identifier, so replies are matched by
        # (identifier, seq) and still count when a device answers from another address.
        base = os.getpid() & 0xFF00
        self.idents = {t.name: (base + i) & 0xFFFF for i, t in enumerate(targets)}
        self.by_ident = {self.idents[t.name]: t for t in targets}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        self.sock.settimeout(0.2)
        # the kernel stamps each reply on arrival, so the RTT stays exact even when this
        # process reads it late; a big buffer holds replies while it's busy
        self.sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMP, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self.expired = {}      # (ident, wire_seq) -> wall send time, of probes declared lost
        self.misread = []      # wall times of replies that came in time but were read too late
        self.send_t = []       # wall-clock send time per round
        self.pending = {}      # (ident, wire_seq) -> (round, perf_counter at send)
        self.tcp_pending = {}  # socket -> (target, round, perf_counter at send)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.start_t = None
        self.slept = None      # (wall time asleep, wall time awake) if the Mac slept
        self.keep = None       # rounds still valid after a sleep

    def run(self):
        threading.Thread(target=self._recv_loop, daemon=True).start()
        threading.Thread(target=self._tcp_loop, daemon=True).start()
        threading.Thread(target=self._send_loop, daemon=True).start()

    def _send_loop(self):
        t0 = time.perf_counter()
        self.start_t = time.time()
        n = 0
        while not self.stop.is_set():
            wait = t0 + n * self.interval - time.perf_counter()
            if wait > 0:
                time.sleep(wait)
            elif wait < -self.interval:
                t0 -= wait     # fell behind: resume from now instead of bursting to catch up
            if self.send_t and (time.time() - self.send_t[-1]) - (time.perf_counter() - last) > 5:
                # The Mac slept (lid closed, empty battery): the wall clock jumped while
                # perf_counter stood still. Rounds around the sleep would count as lost,
                # so keep only those that finished well before it, and stop the test.
                with self.lock:
                    asleep = self.send_t[-1]
                    self.slept = (asleep, time.time())
                    self.keep = bisect.bisect_left(self.send_t, asleep - self.timeout - 2)
                self.stop.set()
                break
            last = time.perf_counter()
            seq = n & 0xFFFF
            wall = time.time()
            payload = struct.pack("!d", wall) + b"netdiag-probe-pad"
            with self.lock:
                self.send_t.append(time.time())
                for t in self.targets:
                    t.rtt.append(...)  # Ellipsis = in flight
                    if t.port:
                        self._send_tcp(t, n)
                        continue
                    ident = self.idents[t.name]
                    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
                    pkt = struct.pack("!BBHHH", 8, 0, icmp_checksum(hdr + payload), ident, seq) + payload
                    self.pending[(ident, seq)] = (n, time.time())    # right before sending
                    try:
                        self.sock.sendto(pkt, (t.addr, 0))
                    except OSError:
                        t.rtt[n] = None   # no route / network down
                        self.pending.pop((ident, seq), None)
                self._expire(n)
            n += 1

    def _send_tcp(self, t, n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        # close with RST instead of FIN: no TIME_WAIT pile-up at 20 connections/s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        t0 = time.perf_counter()
        err = s.connect_ex((t.addr, t.port))
        if err not in (0, errno.EINPROGRESS):
            t.rtt[n] = None
            s.close()
            return
        self.tcp_pending[s] = (t, n, t0)

    def _tcp_loop(self):
        while not self.stop.is_set():
            with self.lock:
                socks = list(self.tcp_pending)
            if not socks:
                time.sleep(0.01)
                continue
            try:
                _, writable, _ = select.select([], socks, [], 0.002)
            except (OSError, ValueError):
                continue
            now = time.perf_counter()
            with self.lock:
                for s in writable:
                    p = self.tcp_pending.pop(s, None)
                    if p is None:
                        continue
                    t, n, t0 = p
                    err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    # "connection refused" is an answer too: the packet made it there and back.
                    # A handshake that took >= 0.9 s only completed because the OS resent the
                    # SYN after its 1 s timeout, i.e. the first SYN or SYN-ACK was lost.
                    answered = err in (0, errno.ECONNREFUSED) and now - t0 < 0.9
                    t.rtt[n] = (now - t0) * 1000 if answered else None
                    s.close()

    def _expire(self, n):
        cutoff = n - int(self.timeout / self.interval) - 1
        for key, (rnd, sent) in list(self.pending.items()):
            if rnd <= cutoff:
                del self.pending[key]
                self.expired[key] = sent
                t = self.by_ident[key[0]]
                t.rtt[rnd], t.lost_at = None, time.time()
        if n % 100 == 0:       # forget expired probes after 10 s (wire seqs wrap around)
            old = time.time() - 10
            self.expired = {k: v for k, v in self.expired.items() if v > old}
        for s, (t, rnd, _) in list(self.tcp_pending.items()):
            if rnd <= cutoff:
                del self.tcp_pending[s]
                t.rtt[rnd], t.lost_at = None, time.time()
                s.close()

    def _recv_loop(self):
        while not self.stop.is_set():
            try:
                data, anc, _, _ = self.sock.recvmsg(2048, 64)
            except socket.timeout:
                continue
            except OSError:
                continue
            now = time.time()
            for lvl, typ, d in anc:
                if lvl == socket.SOL_SOCKET and typ == SCM_TIMESTAMP and len(d) >= 12:
                    sec, usec = struct.unpack("qi", d[:12])
                    now = sec + usec / 1e6
            ihl = (data[0] & 0x0F) * 4 if data and data[0] >> 4 == 4 else 0
            if len(data) < ihl + 8:
                continue
            typ, _, _, ident, seq = struct.unpack("!BBHHH", data[ihl:ihl + 8])
            t = self.by_ident.get(ident)
            if typ != 0 or t is None:
                continue
            with self.lock:
                p = self.pending.pop((ident, seq), None)
                if p is None:
                    sent = self.expired.pop((ident, seq), None)
                    if sent is not None and now - sent < self.timeout:
                        # answered in time, but this Mac was too busy to read it before the
                        # timeout: the tool's fault, not the network's
                        self.misread.append(sent)
                    else:
                        t.late += 1
                    continue
                t.rtt[p[0]] = (now - p[1]) * 1000

    def done_rounds(self):
        """Number of leading rounds whose result is final for every target."""
        with self.lock:
            n = len(self.send_t)
            if not n:
                return 0
            done = max(0, n - int(self.timeout / self.interval) - 1)
            return done if self.keep is None else min(done, self.keep)


# ---------------------------------------------------------------- event classification

def classify(bad, targets, link_label):
    """Which segment does a set of failing targets in one round point at?"""
    hops = sorted((t for t in targets if t.rank < RANK_DEST), key=lambda t: t.rank)
    dests = [t for t in targets if t.rank == RANK_DEST]
    names = {t.name for t in bad}
    router = next((t for t in hops if t.rank == RANK_ROUTER), None)
    if router and router.name in names:
        return "local", f"{link_label} ({router.name} affected)"
    bad_dests = [d for d in dests if d.name in names]
    if dests and len(bad_dests) == len(dests):
        prev = router
        for i, h in enumerate(hops):
            if h.rank == RANK_ROUTER:
                continue
            if all(x.name in names for x in hops[i:]):
                return (segment_for(prev.rank if prev else -1, h.rank),
                        f"between {prev.name if prev else 'you'} and {h.name}")
            prev = h
        return (segment_for(prev.rank if prev else -1, RANK_DEST),
                f"beyond {prev.name if prev else 'you'}")
    bad_hops = [h for h in hops if h.name in names]
    if bad_hops and bad_dests or len({d.addr for d in bad_dests}) >= 2:
        # A drop shorter than a round hits only the probes in flight at that moment,
        # so a real outage can miss some targets; list everything that was hit.
        hit = sorted(bad, key=lambda t: (t.rank, t.port or 0))
        return "partial", f"{len(hit)} of {len(targets)} lost: {', '.join(t.name for t in hit)}"
    if bad_dests:
        return "onedest", f"only {', '.join(d.name for d in bad_dests)}"
    return "ratelimit", f"only {', '.join(sorted(names))} (ICMP rate-limit, harmless)"


def segment_for(prev_rank, next_rank):
    """Segment key for the link between two targets on the path (-1 = this Mac)."""
    if prev_rank < 0:
        return "local"
    if next_rank >= RANK_DEST:
        return "upstream"
    if prev_rank == RANK_ONT:
        return "fiber"
    if prev_rank == RANK_ROUTER:
        return "wan"
    return "isp"


# Texts for the default setup: the ISP's box is modem + router in one.
SEGMENT_TEXT = {
    "local": "your Wi-Fi / LAN link to the home router",
    "wan": "your internet line between the home router and the ISP's first router "
           "(fiber: the box's optical side, splice / fiber cable, OLT; "
           "cable/DSL: modem, line, CMTS/DSLAM; if your ISP rents the line from another "
           "operator, also that operator's access network and the hand-over to your ISP)",
    "fiber": "between the ONT and the ISP (fiber line / ISP's OLT)",
    "isp": "inside the ISP's network, between two of its routers",
    "upstream": "beyond the traced hops (ISP core / internet)",
    "onedest": "a single internet destination only",
    "partial": "a short loss that hit several hops / destinations at once, but not all of them",
    "ratelimit": "an intermediate hop rate-limiting ICMP (harmless)",
    "unclear": "somewhere before the first hop that answered: the devices in between "
               "didn't answer any probe, so it can't be narrowed down",
}

# Short labels for the dashboard and the per-segment table.
SEGMENT_SHORT = {
    "local": "Wi-Fi / LAN",
    "wan": "internet line (router ↔ ISP)",
    "fiber": "fiber (ONT ↔ ISP)",
    "isp": "ISP network",
    "upstream": "beyond traced hops",
    "onedest": "single destination",
    "partial": "short loss, several targets",
    "ratelimit": "hop rate-limit (harmless)",
    "unclear": "before first answering hop",
}

ADVICE = {
    "local": "Fix the local link first: on Wi-Fi see the Wi-Fi findings below (AWDL, "
             "scans, co-channel networks); on Ethernet swap cable/port/adapter.",
    "wan": "Your Wi-Fi/LAN is clean; the loss starts where the line leaves your box. On "
           "fiber: check that the fiber patch cable is firmly plugged in and not kinked or "
           "bent tightly (keep bends wider than a few cm, don't pinch it under furniture or "
           "doors). On cable/DSL: check the coax/phone cable and splitters. Look at the box's "
           "status page / LEDs for line errors or signal levels, and restart the box. If the "
           "loss stays, report it to the ISP's fault hotline with this data. The line and "
           "the ISP's box are theirs to measure and fix.",
    "fiber": "The ONT answers but the ISP's side doesn't: optical line or ISP OLT problem. "
             "Report it to the ISP with this data.",
    "isp": "Your line is clean; packets get lost between two of the ISP's own routers "
           "(congestion or a faulty link in their network). Report it to the ISP with this data "
           "and the hop addresses.",
    "upstream": "Your line and the traced ISP hops are clean; the loss happens deeper in "
                "the ISP network or beyond. Report it to the ISP with this data.",
    "onedest": "Only one internet host loses packets: most likely that host rate-limits "
               "ICMP. Not a problem with your connection.",
    "partial": "Real loss on a shared part of the path; the loss rates per hop show where it "
               "starts. Keep it running for a clearer verdict.",
    "unclear": "Make the devices before that hop answer and run again. On macOS, give your "
               "terminal app access in System Settings → Privacy & Security → Local Network.",
}

# Overrides when a separate ONT/modem with its own IP sits between router and fiber.
SEPARATE_ONT_TEXT = {
    "local": "your Wi-Fi / LAN link to the router",
    "wan": "between the router and the ONT (router WAN port, Ethernet cable, ONT)",
}
SEPARATE_ONT_SHORT = {"local": "Wi-Fi / LAN", "wan": "router ↔ ONT"}
# Overrides when this machine is plugged directly into the ONT (no home router).
DIRECT_ONT_TEXT = {
    "local": "the cable / Ethernet adapter between this computer and the ONT",
    "wan": "the fiber line: ONT optics, fiber / splice, the access network and the "
           "hand-over to the ISP's first router",
}
DIRECT_ONT_SHORT = {"local": "cable Mac ↔ ONT", "wan": "fiber line (ONT ↔ ISP)"}
DIRECT_ONT_ADVICE = {
    "local": "Loss already happens between this computer and the ONT: swap the cable and "
             "the Ethernet adapter, and check the ONT's LAN port.",
    "wan": "This computer is plugged straight into the ONT and the cable to it is clean, "
           "so the loss is on the fiber side: ONT, fiber / splice, the access network or the "
           "hand-over to the ISP. Your home network and router are ruled out. Report it to the "
           "ISP with this data, ideally with the ONT's optical values and error counters.",
}

SEPARATE_ONT_ADVICE = {
    "wan": "Your own link is clean. Check the cable between router and ONT and the router's "
           "WAN port/logs, then restart the ONT.",
}


class EventTracker:
    """Turns finalized probe rounds into merged loss / spike events."""

    def __init__(self, prober, link_label):
        self.p, self.link = prober, link_label
        self.done = 0
        self.events = []            # dicts
        self.open = {}              # kind -> event dict being extended
        self.windows = {t.name: deque(maxlen=2000) for t in prober.targets}
        self.base = {}              # target name -> rolling p50
        self.dead = set()           # targets that don't answer at all (ignored)
        self.loss_t = []            # send times of rounds where something was lost
        self.lost = Counter()       # target name -> lost probes so far
        self.periodic, self._period_at = None, 0
        self.scroll, self.seen, self.page = 0, 0, 1    # dashboard: events list position

    def update(self):
        upto = self.p.done_rounds()
        targets = self.p.targets
        for n in range(self.done, upto):
            if n in (40, 200) or (n and n % 1000 == 0):
                # a device that ignores this probe type would look like a permanent outage
                w = min(n, 200)
                silent = {t.name for t in targets
                          if sum(1 for v in t.rtt[n - w:n] if v is None) >= 0.9 * w}
                # if nothing answered, that's an outage, not devices ignoring the probe type
                if len(silent) < len(targets):
                    self.dead = silent
            for t in targets:
                if t.rtt[n] is None:
                    self.lost[t.name] += 1
            alive = [t for t in targets if t.name not in self.dead]
            lost = [t for t in alive if t.rtt[n] is None]
            spiky = []
            for t in alive:
                v = t.rtt[n]
                if isinstance(v, float):
                    b = self.base.get(t.name)
                    # same rule as the yellow bars in the dashboard
                    if b and not t.port and v > b + SPIKE_MS:
                        spiky.append(t)
                    self.windows[t.name].append(v)
            if lost:
                self.loss_t.append(self.p.send_t[n])
            self._feed("loss", n, lost, alive)
            self._feed("spike", n, spiky, alive)
            for name, w in self.windows.items():
                if len(w) >= 20 and (n % 200 == 0 or name not in self.base):
                    self.base[name] = statistics.median(w)
        self.done = max(self.done, upto)

    def _feed(self, kind, n, bad, alive):
        ev = self.open.get(kind)
        gap = max(1, int(0.25 / self.p.interval))   # merge rounds closer than 250 ms
        if bad:
            seg, _ = classify(bad, alive, self.link)
            if ev and ev["seg"] == seg and n - ev["last"] <= gap:
                ev["last"] = n
                ev["rounds"] += 1
                ev["targets"] |= {t.name for t in bad}
                if kind == "spike":
                    ev["peak"] = max(ev["peak"], max(t.rtt[n] for t in bad))
            else:
                ev = {"kind": kind, "seg": seg, "first": n, "last": n, "rounds": 1,
                      "t": self.p.send_t[n], "targets": {t.name for t in bad},
                      "peak": max(t.rtt[n] for t in bad) if kind == "spike" else None}
                self.open[kind] = ev
                self.events.append(ev)
            # just what failed, in path order (targets are sorted by hop)
            ev["desc"] = ", ".join(t.name for t in self.p.targets if t.name in ev["targets"])

    def period(self, force=False):
        """Recurring-loss check (see find_period), redone at most every 10 s while live."""
        if self.done and (force or time.time() - self._period_at > 10):
            self._period_at = time.time()
            self.periodic = find_period(self.loss_t, self.p.send_t[0],
                                        self.p.send_t[self.done - 1], self.p.interval)
        return self.periodic

    def tally(self, kind="loss"):
        c = Counter()
        for e in self.events:
            if e["kind"] == kind:
                c[e["seg"]] += 1
        return c


# ---------------------------------------------------------------- live dashboard

SPARK = " ▁▂▃▄▅▆▇█"
SPIKE_MS = 20       # extra delay over a target's median that counts as a latency spike
# dark yellow (256-color): still readable on light backgrounds, unlike plain yellow
WARN = "38;5;178"
GREY = "38;5;243"
HELP = "38;5;249"   # explanations: softer than normal text, brighter than GREY   # darker than the terminal's "bright black", readable on light backgrounds


def color(s, code, enabled):
    return f"\x1b[{code}m{s}\x1b[0m" if enabled else s


def probe_label(t):
    return f"tcp:{t.port}" if t.port else "icmp"


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def fit(line, width):
    """Cut a line to `width` visible characters; color codes don't count."""
    out, vis, pos = [], 0, 0
    for m in ANSI_RE.finditer(line):
        chunk = line[pos:m.start()][:max(0, width - vis)]
        out.append(chunk)
        vis += len(chunk)
        out.append(m.group())
        pos = m.end()
    out.append(line[pos:][:max(0, width - vis)])
    return "".join(out) + "\x1b[0m"


def spark_cells(t, end, n_cols, per_col, base):
    """One column per second: (ping cells, loss cells). Ping = how far the highest RTT of
    that second is above the target's median; loss = how many probes got lost (1-9, # for 10+)."""
    ping, loss = [], []
    for c in range(n_cols):
        a = end - (n_cols - c) * per_col
        b = a + per_col
        if b <= 0:
            ping.append((" ", None))
            loss.append((" ", None))
            continue
        vals = t.rtt[max(0, a):b]
        lost = sum(1 for v in vals if v is None)
        loss.append((str(lost) if lost < 10 else "#", "1;31") if lost else (" ", None))
        nums = [v for v in vals if isinstance(v, float)]
        if not nums:
            ping.append((" ", None))
            continue
        # height = extra delay over the target's median in ms; normal jitter (< 5 ms) stays
        # a flat line so the losses stand out. Yellow = a spike, the same rule as the events
        # (TCP handshake timing is too uneven to call spikes, like there).
        if base and max(nums) - base > SPIKE_MS:
            ping.append((SPARK[8], None if t.port else WARN))
            continue
        # otherwise a typical reply of that second (3rd quartile), not the single slowest of
        # up to 20, which would turn every bit of jitter into a bump
        extra = sorted(nums)[len(nums) * 3 // 4] - base if base else 0
        ping.append((SPARK[1 if extra < 5 else 2 if extra < 10 else 4], None))
    return ping, loss


def vis_len(s):
    return len(ANSI_RE.sub("", s))


INTERVAL_HELP = (
    "A device on the path may run a job every few seconds that briefly loses packets. Every "
    "interval in the range shown and every moment within it is tried. \"when\" = at which moment of the "
    "cycle the losses happen, as seconds of the clock: \"at :24.19 and :54.19 of every "
    "minute\" = 12:00:24.19, 12:00:54.19, 12:01:24.19, …; intervals that don't fit evenly "
    "into a minute show the clock time of their first loss. "
    "\"spread\" = how tightly the losses cluster around that moment; \"drift\" = how fast "
    "that moment moves (a device clock running slightly fast or slow; measured from 30 min); "
    "\"seen\" = in how many cycles there was a loss at that moment, \"expected\" = how many "
    "cycles would have a loss at that moment anyway, if the same number of losses happened at "
    "random times. \"Chance it's "
    "just luck\" says how "
    "rarely random loss alone would produce the best pattern found (taking into account that "
    "all intervals were searched): 1 in 10 000 or rarer is statistically significant, 1 in "
    "1 000 possibly significant (a longer run will tell).")


def odds(p):
    """A probability as "1 in N" with a readable N."""
    if p >= 0.5:
        return "likely luck"
    if p < 1e-12:      # also catches p == 0 (underflow on very long runs)
        return "1 in over a trillion"
    n = 1 / p
    for limit, word in ((1e12, "trillion"), (1e9, "billion"), (1e6, "million")):
        if n >= limit:
            return "1 in over a trillion" if limit == 1e12 else f"1 in {n / limit:.0f} {word}"
    step = 10 ** max(0, int(math.log10(n)) - 1)     # two significant digits
    return f"1 in {round(n / step) * step:,.0f}".replace(",", " ")


def significance(c):
    """2 = statistically significant, 1 = possibly (a longer run would tell), 0 = not."""
    return 2 if c["p_adj"] <= 1e-4 and c["hits"] >= 4 else 1 if c["p_adj"] <= 1e-3 else 0


SIGNIFICANCE = [("statistically not significant", GREY), ("possibly significant", WARN),
                ("statistically significant", "1;31")]


def phase_drift(c, times):
    """How fast the moment of a timer moves, in seconds per hour (a device clock that runs
    a bit fast or slow), from a line fit through the hits. 0.0 = no measurable drift,
    None = too few hits or too short to tell (needs 30 min)."""
    P, ph, w = c["period"], c["phase"], c["window"]
    pts = [(t, (t - ph + P / 2) % P - P / 2) for t in times
           if abs((t - ph + P / 2) % P - P / 2) <= w / 2]
    if len(pts) < 8 or pts[-1][0] - pts[0][0] < 1800:
        return None
    mt = statistics.mean(t for t, _ in pts)
    md = statistics.mean(d for _, d in pts)
    var = sum((t - mt) ** 2 for t, _ in pts)
    slope = sum((t - mt) * (d - md) for t, d in pts) / var
    resid = sum((d - md - slope * (t - mt)) ** 2 for t, d in pts) / (len(pts) - 2)
    se = math.sqrt(resid / var)
    # only a trend clearly larger than its uncertainty counts
    return slope * 3600 if abs(slope) > 3 * se else 0.0


def interval_blocks(prober, tracker, use_color, window_s=300):
    """Regular loss intervals for the whole run and, once it's long enough, the last
    `window_s` seconds (where a drifting timer is now): blocks of lines (see period_scan)."""
    now = time.time()
    cache = getattr(tracker, "_intervals", None)
    busy = getattr(tracker, "_intervals_busy", None)
    # rescan every 5 s, less often on long runs (the scan grows with the run, the pattern
    # changes slowly): 1 min after 30 min
    every = max(5, (now - prober.send_t[0]) / 30) if prober.send_t else 5
    tracker._intervals_every = every
    if busy and busy.done():
        try:
            tracker._intervals = (tracker._intervals_at, _interval_blocks(busy.result(), use_color))
        except Exception:
            tracker._intervals_at = now     # keep showing the previous result
        busy = tracker._intervals_busy = None
        cache = tracker._intervals
    if cache and (now - cache[0] < every or busy):
        return cache[1]
    done = tracker.done
    end = prober.send_t[done - 1] if done else now
    job = (list(tracker.loss_t), prober.send_t[0] if done else now, end, prober.interval, window_s)
    if cache is not None:
        # long runs take seconds to scan: do it in another process, so it neither holds up
        # the drawing nor takes CPU time (the interpreter lock) from the probe threads
        global _POOL
        if _POOL is None:
            _POOL = concurrent.futures.ProcessPoolExecutor(1, initializer=_ignore_sigint)
        tracker._intervals_busy, tracker._intervals_at = _POOL.submit(scan_views, *job), now
        return cache[1]
    tracker._intervals = (now, _interval_blocks(scan_views(*job), use_color))
    return tracker._intervals[1]


_POOL = None


def _ignore_sigint():
    signal.signal(signal.SIGINT, signal.SIG_IGN)     # Ctrl+C is the main process's business


def scan_views(loss_t, first, end, interval, window_s):
    """Loss intervals for the whole run and, once it's long enough, the last `window_s`
    seconds: [(label, start, end, interval, losses, candidates)]."""
    views = [("whole run", first)]
    if end - first > 2 * window_s:   # the moment of a timer can drift
        views.append((f"last {window_s // 60} min", end - window_s))
    out = []
    for label, start in views:
        times = [t for t in loss_t if t >= start]
        n = len([t for i, t in enumerate(times) if not i or t - times[i - 1] > 0.3])
        found, masked = [], 0.0
        while len(found) < 8:
            cands = period_scan(times, start, end, interval, masked=masked)
            if not cands or (len(found) >= 5 and not significance(cands[0])):
                break       # the 5 best guesses, plus any further (possibly) significant ones
            cands[0]["drift"] = phase_drift(cands[0], times)
            found.append(cands[0])
            # losses this interval explains don't count for the next candidate (a 30 s timer
            # would otherwise also show up as 20 s, 45 s, ... sharing some of its losses)
            c = cands[0]
            P, ph = c["period"], c["phase"]
            times = [t for t in times if abs((t - ph + P / 2) % P - P / 2) > c["window"]]
            # those losses' time is gone too, or the gaps left behind would make multiples
            # of this interval look regular
            masked = min(0.9, masked + 2 * c["window"] / P)
        out.append((label, start, end, interval, n, found))
    return out


def _interval_blocks(views, use_color):
    blocks = []
    for label, start, end, interval, n, found in views:
        sig = sum(1 for c in found if significance(c) == 2)
        maybe = sum(1 for c in found if significance(c) == 1)
        if not found:
            summary = "not enough losses to test yet"
        elif sig or maybe:
            summary = ", ".join(x for x in (
                sig and f"{sig} statistically significant interval{'s' * (sig != 1)}",
                maybe and f"{maybe} possibly significant") if x)
        else:
            summary = "no statistically significant interval (best guesses below)"
        lo, hi = 1 if interval <= 0.2 else 5, int(min(300, (end - start) / 3))
        checked = f"intervals {lo}–{hi} s checked" if hi >= lo and n >= 4 else "nothing checked yet"
        out = [color(f"{label}: {n} losses in {(end - start) / 60:.1f} min", "1", use_color)
               + color(f" · {checked}", GREY, use_color),
               "  " + summary]
        ats = [moment_text(c["period"], c["phase"], start) for c in found]
        aw = max([len(a) for a in ats] + [4])
        if found:
            out.append(color(f"  every  {'when':<{aw}} spread  drift       seen        "
                             "expected    chance it's just luck  result", GREY, use_color))
        for c, at in zip(found, ats):
            label, code = SIGNIFICANCE[significance(c)]
            exp = c["expected"]
            hit = f"{c['hits']:>3} of {c['cycles']:<4}  ~{exp:.0f}" if exp >= 1 else \
                f"{c['hits']:>3} of {c['cycles']:<4}  <1"
            d = c.get("drift")
            drift = f"{'-' if d is None else 'none' if d == 0 else f'{d * 1000:+.0f} ms/h':<10}"
            out.append(f"  {c['period']:>3} s  {at:<{aw}} {c['spread'] * 1000:>4.0f} ms  {drift}  {hit:<21}   "
                       f"{odds(c['p_adj']):<21}  "
                       + color(label, code, use_color))
        blocks.append(out)
    return blocks


def clock(t, decimals=1):
    return time.strftime("%H:%M:%S", time.localtime(t)) + f".{int(t * 10 ** decimals) % 10 ** decimals:0{decimals}d}"


def headline(title, cols, use_color):
    return color(f"── {title} " + "─" * max(0, cols - len(title) - 5), "1", use_color)


def event_line(e, interval, use_color):
    ts = clock(e["t"])
    dur = fmt_dur(e["rounds"] * interval)
    if e["kind"] == "loss":
        return f"{ts}  {color('LOSS ', '1;31', use_color)}  {dur:>7}  {e['desc']}"
    return (f"{ts}  {color('SPIKE', WARN, use_color)}  {dur:>7}  {e['desc']} "
            f"(up to {e['peak']:.0f} ms)")


def events_view(tracker, interval, cols, space, use_color):
    """The events section in `space` lines: newest at the bottom, or scrolled back with
    the arrow / page keys (tracker.scroll = events hidden below the view)."""
    events, total = tracker.events, len(tracker.events)
    rows = max(0, space - 2)            # headline (with the scroll hint), column header
    if tracker.scroll:                  # scrolled back: keep the view still as events arrive
        tracker.scroll += total - tracker.seen
    tracker.seen, tracker.page = total, max(1, rows)
    tracker.scroll = max(0, min(tracker.scroll, total - rows))
    end = total - tracker.scroll
    shown = events[max(0, end - rows):end] if rows else []
    title = (f"Events {end - len(shown) + 1}–{end} of {total}" if total > len(shown) and shown
             else f"Events ({total})")
    head = headline(title, cols, use_color)
    if total > len(shown):
        older, newer = end - len(shown), tracker.scroll
        hint = (f" ▲ {older} older · ▼ {newer} newer   ↑/↓ scroll · PgUp/PgDn page · "
                "Home/End oldest/newest" + ("" if newer else " · following newest") + " ")
        line = f"── {title} "
        line += "─" * max(1, cols - 1 - len(line) - len(hint) - 2)
        head = color(line, "1", use_color) + color(hint, GREY, use_color) + color("──", "1", use_color)
    out = [head, color("time        type    lasted  targets", GREY, use_color)]
    out += [event_line(e, interval, use_color) for e in shown]
    return out


def read_keys(tracker, stop):
    """Arrow / page keys scroll the events list (terminal in cbreak mode; Ctrl+C still works)."""
    fd = sys.stdin.fileno()
    keys = {b"\x1b[A": 1, b"k": 1, b"\x1b[B": -1, b"j": -1, b"\x1b[5~": "pg", b"\x1b[6~": "-pg",
            b"\x1b[H": "home", b"\x1b[1~": "home", b"g": "home",
            b"\x1b[F": "end", b"\x1b[4~": "end", b"G": "end"}
    while not stop.is_set():
        if not select.select([fd], [], [], 0.2)[0]:
            continue
        k = keys.get(os.read(fd, 16))
        if k == "pg":
            k = tracker.page
        elif k == "-pg":
            k = -tracker.page
        if k == "home":
            tracker.scroll = len(tracker.events)
        elif k == "end":
            tracker.scroll = 0
        elif k:
            tracker.scroll = max(0, tracker.scroll + k)


def render(prober, tracker, link_desc, wifi_now, started, use_color, drawn):
    """Draw the dashboard over the previous frame (`drawn` lines). Returns lines drawn."""
    cols, term_rows = shutil.get_terminal_size((100, 30))
    done = tracker.done
    targets = prober.targets
    el = time.time() - started
    lines = []
    top = (color("netdiag", "1", use_color) +
           f"  {link_desc}  ·  {int(el // 60)}m{int(el % 60):02d}s  ·  "
           f"{done} rounds @ {prober.interval * 1000:.0f} ms  ·  Ctrl+C = stop + report")
    if wifi_now:       # Wi-Fi link state, right-aligned on the same line
        w = wifi_now[-1]
        wifi = (f"Wi-Fi ch {w['channel']} · {w['rssi']} dBm · SNR {w['rssi'] - w['noise']} dB · "
                f"{w['rate']:.0f} Mbps")
        top += " " * max(2, cols - 1 - vis_len(top) - len(wifi)) + wifi
    lines.append(top)
    lines.append(headline("Probes", cols, use_color))
    label = lambda t: f"{t.addr}:{t.port}" if t.port else t.addr
    aw = max(len(label(t)) for t in targets) + 2
    left_w = 4 + aw + 29                 # hop, address, loss / last / p50 / p95
    spark_w = max(10, cols - left_w - 4)
    per_col = max(1, round(1 / prober.interval))     # one column = one second
    spark_end = done // per_col * per_col   # only complete seconds: shifts once per second
    lines.append(f"{'hop':>3} {'address':<{aw}}{'loss':>8}{'last':>7}{'p50':>7}"
                 f"{'p95':>7}   last {spark_w}s · bar = ping above p50 (+5/10 ms, " + color(f"█ spike +{SPIKE_MS}", WARN, use_color) + ") · "
                 + color("digit", "1;31", use_color) + " = lost/s")
    # percentiles of the recent replies, refreshed every 5 s: sorting them on every frame
    # would eat the CPU time the probe threads need on long runs
    cache = getattr(tracker, "_pcts", None)
    if not cache or done - cache[0] >= 5 * per_col or done < cache[0]:
        cache = tracker._pcts = (done, {})
        for t in targets:
            nums = sorted(v for v in t.rtt[max(0, done - 20000):done] if isinstance(v, float))
            cache[1][t.name] = (pct(nums, 50), pct(nums, 95)) if nums else (None, None)
    for t in targets:
        lost = tracker.lost[t.name]
        last = next((t.rtt[i] for i in range(done - 1, max(-1, done - 200), -1)
                     if isinstance(t.rtt[i], float)), None)
        p50, p95 = cache[1][t.name]
        f = lambda v: f"{v:7.1f}" if v is not None else "      -"
        loss = 100 * lost / done if done else 0
        ls = f"{loss:7.2f}%"
        rest = f"{f(last)}{f(p50)}{f(p95)}"
        left = f"{t.hop or '-':>3} {label(t):<{aw}}"
        if time.time() - t.lost_at < 0.15:
            # flash the row the moment a probe is declared lost (redrawn 10×/s)
            left = color(left + ls + rest, "1;97;41", use_color)
        else:
            left += (color(ls, "1;31", use_color) if loss >= 0.5 else ls) + rest
        ping, lossc = spark_cells(t, spark_end, spark_w, per_col, p50)
        paint = lambda cells: "".join(color(ch, c, use_color) if c else ch for ch, c in cells)
        lines.append(f"{left}   {paint(ping)}")
        # loss row right under its ping row; stays empty while nothing is lost
        name = f"{t.name[:aw - 1]:<{aw}}"
        lines.append("    " + color(name, GREY, use_color) + " " * (left_w - 10 - aw)
                     + color("lost/s", GREY, use_color) + "   " + paint(lossc))
    lines.append("")
    blocks = interval_blocks(prober, tracker, use_color)
    if getattr(tracker, "_intervals_busy", None):
        status = "recalculating…"
    else:
        age = time.time() - tracker._intervals[0]
        status = (f"updated {age:.0f} s ago, next in "
                  f"{max(0, tracker._intervals_every - age):.0f} s")
    lines.append(headline(f"Regular loss intervals · {status}", cols, use_color))
    lines += [color(l, HELP, use_color) for l in wrap(INTERVAL_HELP, cols - 2, "").split("\n")]
    lines.append("")
    w = max(map(vis_len, blocks[0])) + 6
    if len(blocks) == 2 and cols - 1 >= w + max(map(vis_len, blocks[1])):  # side by side
        for i in range(max(map(len, blocks))):
            a = blocks[0][i] if i < len(blocks[0]) else ""
            b = blocks[1][i] if i < len(blocks[1]) else ""
            lines.append(a + " " * (w - vis_len(a)) + b)
    else:
        for i, b in enumerate(blocks):
            lines += ([""] if i else []) + b
    # newest events at the bottom, as many as fit; the frame must fit on screen, or
    # moving the cursor back up can't reach its top
    lines.append("")
    lines += events_view(tracker, prober.interval, cols, term_rows - 1 - len(lines), use_color)
    lines = lines[:max(1, term_rows - 1)]
    up = f"\x1b[{drawn}F" if drawn else ""   # back to the first line of the previous frame
    out = up + "".join(fit(l, cols - 1) + "\x1b[K\n" for l in lines) + "\x1b[J"
    sys.stdout.write(out)
    sys.stdout.flush()
    return len(lines)


# ---------------------------------------------------------------- run

def cmd_run(args):
    gw, iface = default_route()
    if not iface:
        sys.exit("No default route. Are you connected?")
    iface = physical_iface(iface)
    link = detect_link(iface, args.link)
    port = hardware_ports().get(iface, iface)
    link_label = "Wi-Fi" if link == "wifi" else "Ethernet/LAN"
    print(f"Connection: {link_label} on {iface} ({port}), router {gw}")

    ont = args.ont
    # Direct mode: this machine is plugged straight into the ONT (no home router), so
    # the ONT is on-link and the default gateway is already the ISP's first router.
    direct = bool(ont) and on_link(ont)
    if ont and not direct and is_router_itself(ont):
        print(f"  {ont} answers as hop 1, so it's an address of the router itself, not an ONT. "
              "Ignoring --ont.")
        ont = None
    targets = []
    if direct:
        SEGMENT_TEXT.update(DIRECT_ONT_TEXT)
        SEGMENT_SHORT.update(DIRECT_ONT_SHORT)
        ADVICE.update(DIRECT_ONT_ADVICE)
        targets.append(Target("ont", ont, RANK_ROUTER))
        print(f"  Setup: this Mac → ONT {ont} (directly attached) → fiber → ISP gateway {gw}")
    elif gw:
        targets.append(Target("home-router", gw, RANK_ROUTER, hop=1))
    if direct:
        pass
    elif ont:
        SEGMENT_TEXT.update(SEPARATE_ONT_TEXT)
        SEGMENT_SHORT.update(SEPARATE_ONT_SHORT)
        ADVICE.update(SEPARATE_ONT_ADVICE)
        targets.append(Target("ont", ont, RANK_ONT))
        print(f"  Setup: router {gw} → ONT {ont} → fiber")
    else:
        print(f"  Setup: home router {gw} is also the modem (fiber box / modem-router); "
              "use --ont IP if you have a separate ONT/modem")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(args.out, stamp)
    os.makedirs(out_dir, exist_ok=True)

    print(f"Tracing the route to {', '.join(args.hosts)}...")
    traces = trace_all(args.hosts)
    with open(os.path.join(out_dir, "traceroute.txt"), "w") as f:
        for d, (raw, _) in traces.items():
            f.write(f"== {d}\n{raw}\n")
    raw, hops = traces[args.hosts[0]]
    # in direct mode the gateway is hop 1 and is the ISP's first router, so probe it too
    skip = (ont, *args.hosts) if direct else (gw, ont, *args.hosts)
    first_isp = 1 if direct else 2
    hops = [(n, ip) for n, ip in hops if n <= args.hops and ip not in skip]
    pingable = answers_echo([ip for _, ip in hops])
    for n, ip in hops:
        if ip in pingable:
            isp = n == first_isp and (direct or not ont)
            targets.append(Target(f"hop{n}" + ("-isp" if isp else ""), ip, RANK_HOP + n, hop=n))
            print(f"  hop {n:>2}: {ip}")
        else:
            print(f"  hop {n:>2}: {ip} (doesn't answer pings, skipped)")
    for h in args.hosts:
        hop = next((n for n, ip in traces[h][1] if ip == h), None)
        targets.append(Target(h, h, RANK_DEST, hop=hop))
        print(f"  hop {hop if hop else '?':>2}: {h}" + ("" if hop else " (not reached by traceroute)"))
    if direct and gw and gw not in [ip for _, ip in hops] and gw in answers_echo([gw]):
        targets.append(Target("isp-gw", gw, RANK_HOP, hop=1))
        print(f"  hop  1: {gw} (ISP gateway, answers from another address in traceroute)")
    if args.tcp:
        tcp = ([("ont", ont, RANK_ROUTER, None)] if ont else []) + \
              [(t.name, t.addr, RANK_DEST, t.hop) for t in targets if t.rank == RANK_DEST]
        for name, addr, rank, hop in tcp:
            port = open_tcp_port(addr)
            if port:
                targets.append(Target(f"{name}:{port}", addr, rank, hop=hop, port=port))
                print(f"  TCP {addr}:{port} (handshake timing, like real traffic)")
            else:
                print(f"  TCP {addr}: no open port 80/443, skipped")
    targets.sort(key=lambda t: t.rank)
    check_local_network_access(targets)

    full, link_samples, sampler = None, [], None
    counters_before = iface_counters(iface)
    err_samples = []    # (time, input errors) to correlate with loss events

    def sample_errors():
        while not prober.stop.is_set():
            c = iface_counters(iface)
            if c:
                err_samples.append((time.time(), c["ierrs"]))
            prober.stop.wait(0.5)
    if link == "wifi":
        sampler = start_link_sampler(2.0, out_dir, link_samples)

    # hand the interpreter lock over every 1 ms (default 5 ms), so the analysis threads
    # don't delay the probe threads' timestamps
    sys.setswitchinterval(0.001)
    prober = Prober(targets, args.interval)
    tracker = EventTracker(prober, link_label)
    started = time.time()
    prober.run()
    threading.Thread(target=sample_errors, daemon=True).start()
    tty = sys.stdout.isatty()
    term = None
    if tty:
        sys.stdout.write("\n\x1b[?25l")   # hide cursor
        if sys.stdin.isatty():
            # keys without Enter and without echo, for scrolling the events list
            term = termios.tcgetattr(sys.stdin)
            ttymode.setcbreak(sys.stdin)
            threading.Thread(target=read_keys, args=(tracker, prober.stop), daemon=True).start()
    last_plain = last_save = 0
    drawn = 0   # lines of the previous frame, redrawn in place so the last one stays visible
    try:
        while True:
            time.sleep(0.1 if tty else 0.5)
            tracker.update()
            if tty:
                drawn = render(prober, tracker, f"{link_label} {iface}", link_samples, started,
                               True, drawn)
            elif time.time() - last_plain >= 5:
                last_plain = time.time()
                d = tracker.done
                print(f"{time.time() - started:6.0f}s  " + "  ".join(
                    f"{t.name}={sum(1 for v in t.rtt[:d] if v is None)}/{d}" for t in targets),
                    flush=True)
            if time.time() - last_save >= 10:
                last_save = time.time()
                save_probes(prober, tracker.done, out_dir)
            if args.duration and time.time() - started >= args.duration:
                break
            if prober.slept:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if term:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, term)
        if tty:
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()
    prober.stop.set()
    if _POOL:
        for proc in list(_POOL._processes.values()):    # don't wait for a running scan
            proc.terminate()
        _POOL.shutdown(wait=False, cancel_futures=True)
    if sampler:
        sampler.terminate()
    tracker.update()
    if prober.slept:
        asleep, awake = prober.slept
        print(f"\nThe Mac was asleep from {time.strftime('%H:%M:%S', time.localtime(asleep))} "
              f"to {time.strftime('%H:%M:%S', time.localtime(awake))}, so the test stopped "
              "there. The report covers the time before the sleep.")
    if link == "wifi":
        # A neighbor scan takes the radio off-channel, so it only runs after the test, and
        # only when the Wi-Fi hop itself lost packets (otherwise Wi-Fi is ruled out anyway).
        router = next((t for t in targets if t.rank == RANK_ROUTER
                       and t.name not in tracker.dead), None)
        lost = sum(1 for v in router.rtt[:tracker.done] if v is None) if router else 0
        if router and lost >= 3 and lost >= 0.001 * tracker.done:
            print(f"\n{router.name} lost {lost} packets, so scanning Wi-Fi neighbors...")
            full = wifi_snapshot(iface)
        else:
            full = {"awdl_up": awdl_up(), "scan_skipped": router.name if router else "router"}
    setup = "direct" if direct else "router+ont" if ont else "router"
    report(prober, tracker, link, iface, full, link_samples, counters_before, out_dir, err_samples,
           setup)


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)
        return len(s)

    def flush(self):
        for st in self.streams:
            st.flush()


def report(prober, tracker, link, iface, full, link_samples, counters_before, out_dir, err_samples,
           setup="router"):
    """Print the report, keep a copy in report.txt and write summary.json."""
    info = {}
    with open(os.path.join(out_dir, "report.txt"), "w") as f, \
            contextlib.redirect_stdout(Tee(sys.stdout, f)):
        stats = _report(prober, tracker, link, iface, full, link_samples, counters_before,
                        out_dir, err_samples, info)
        if stats:
            write_summaries(prober, tracker, stats, info, link, setup, out_dir)


def save_probes(prober, upto, out_dir):
    """Append the finished rounds to probes.csv (during the run too, so a crash, a kill or
    a dead battery doesn't lose the night's data)."""
    start = getattr(prober, "saved", 0)
    with open(os.path.join(out_dir, "probes.csv"), "a" if start else "w") as f:
        if not start:
            f.write("round,send_time," + ",".join(t.name for t in prober.targets) + "\n")
        for n in range(start, upto):
            f.write(f"{n},{prober.send_t[n]:.4f}," + ",".join(
                f"{t.rtt[n]:.3f}" if isinstance(t.rtt[n], float) else "" for t in prober.targets)
                    + "\n")
    prober.saved = max(start, upto)


def _report(prober, tracker, link, iface, full, link_samples, counters_before, out_dir, err_samples,
            info):
    done = tracker.done
    targets = prober.targets
    if not done:
        print("Stopped before any probe round completed.")
        return None

    save_probes(prober, done, out_dir)
    with open(os.path.join(out_dir, "events.json"), "w") as f:
        json.dump([{**e, "targets": sorted(e["targets"])} for e in tracker.events], f, indent=1)
    with open(os.path.join(out_dir, "events.txt"), "w") as f:
        f.write("time        type    lasted  targets\n")
        f.writelines(event_line(e, prober.interval, False) + "\n" for e in tracker.events)
    if link_samples or full:
        with open(os.path.join(out_dir, "wifi.json"), "w") as f:
            json.dump({"scan": full, "samples": link_samples}, f, indent=1)

    dur = prober.send_t[done - 1] - prober.send_t[0]
    print(f"\nRan {dur / 60:.1f} min, {done} probe rounds every {prober.interval * 1000:.0f} ms. "
          f"Raw data: {out_dir}/")
    print(f"Command: {' '.join(['netdiag.py'] + sys.argv[1:])}")
    if prober.slept:
        print(f"Stopped early: the Mac went to sleep at "
              f"{time.strftime('%H:%M:%S', time.localtime(prober.slept[0]))}.")
    if prober.misread:
        print(f"⚠ This Mac was too busy to read {len(prober.misread)} replies in time (first at "
              f"{time.strftime('%H:%M:%S', time.localtime(prober.misread[0]))}): they arrived "
              "within the timeout but count as lost, so ICMP loss is overstated. Close other "
              "heavy apps and run again.")
    kinds = Counter(e["kind"] for e in tracker.events)
    print(f"Events: {kinds['loss']} loss, {kinds['spike']} latency spike, all listed in events.txt")

    findings = []
    stats = {}
    for t in targets:
        series = analyze_series({n: t.rtt[n] for n in range(done)}, prober.interval)
        stats[t.name] = series
        print_series(f"{t.name} ({t.addr}, hop {t.hop or '?'}, {probe_label(t)})", series)
        if t.late:
            print(f"  late      {t.late} replies arrived after the {prober.timeout:.0f}s timeout")
        if t.rank == RANK_ROUTER:
            findings += findings_for(series, t.name, link, modes=not t.port)
        elif t.rank == RANK_DEST:
            findings += findings_for(series, t.name, link, loss=False, modes=not t.port)
    # with a clean first hop, Wi-Fi can't be what loses the internet packets
    router = next((stats[t.name] for t in targets if t.rank == RANK_ROUTER
                   and t.name not in tracker.dead), None)
    local_clean = bool(router) and router["loss_pct"] < 0.1
    findings += loss_pattern([t for t in targets if t.rank == RANK_DEST], stats,
                             "ethernet" if local_clean else link)

    findings = localize(tracker, targets, stats, prober.interval, info) + findings
    per = tracker.period(force=True)
    info["periodic"] = per
    if per:
        P, w = per["period"], per["window"] / 2
        in_win = [n for n in range(done)
                  if abs((prober.send_t[n] - per["phase"] + P / 2) % P - P / 2) <= w]
        alive = sorted((t for t in targets if t.name not in tracker.dead),
                       key=lambda t: (t.rank, t.port or 0))
        hit = [t for t in alive if any(t.rtt[n] is None for n in in_win)]
        where = ""
        if hit and hit[0] is not alive[0]:
            ok = [t.name for t in alive[:alive.index(hit[0])]]
            where = (f" {', '.join(ok)} never lost a packet at those moments, "
                     f"{hit[0].name} and later targets did, so it's from {hit[0].name} on.")
        per["first_hit"] = hit[0].name if hit else None
        findings.insert(1, ("!", f"The losses recur on a fixed timer: {period_text(per)}; "
                            f"{per['share'] * 100:.0f}% of all loss rounds fall in that window. "
                            "Random loss doesn't do that: a device on the path runs a periodic "
                            f"job that briefly stops forwarding.{where}"))
    if all(s["loss_pct"] >= 90 for s in stats.values()):
        findings = [("!", "Nothing answered at all: the connection was down during this run "
                     "(cable unplugged, no address from the ISP, or VPN/firewall blocking).")]
    for name in sorted(tracker.dead):
        findings.append(("i", f"{name} never answered this kind of probe, so it was left out of "
                         "the analysis (the device ignores it, not a connection problem)."))
    if link == "wifi":
        wifi = [{**(full or {}), **s} for s in link_samples] or ([full] if full else [])
        findings += wifi_findings(wifi)
    else:
        findings += ethernet_findings(iface, counters_before, iface_counters(iface))
    findings += error_correlation(tracker, err_samples, iface)
    print_findings(findings)
    return stats


def write_summaries(prober, tracker, stats, info, link, setup, out_dir):
    """summary.json, read by `summarize` to compare runs."""
    done = tracker.done
    rows = []
    for t in prober.targets:
        r = stats[t.name]
        rows.append({"name": t.name, "addr": t.addr, "hop": t.hop, "probe": probe_label(t),
                     "rank": t.rank, "sent": r["sent"], "lost": r["lost"],
                     "loss_pct": round(r["loss_pct"], 3),
                     "p50": round(r["p50"], 2) if "p50" in r else None,
                     "silent": t.name in tracker.dead})
    summary = {"start": prober.send_t[0], "end": prober.send_t[done - 1], "rounds": done,
               "interval": prober.interval, "link": link, "setup": setup, "targets": rows,
               "verdict": info.get("verdict"), "shared": info.get("shared"),
               "periodic": info.get("periodic"), "slept": prober.slept, "misread": len(prober.misread), "argv": sys.argv[1:]}
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)


def cmd_summarize(args):
    """Compare several runs (e.g. different times of day) side by side."""
    paths = sorted(p for d in args.dirs for p in glob.glob(os.path.join(d, "**", "summary.json"),
                                                           recursive=True))
    if not paths:
        sys.exit("No summary.json found (runs made with this version of netdiag write one).")
    head = ("| start | min | setup | probe | first device | ISP first hop | internet ICMP "
            "| internet TCP | loss starts | periodic |")
    lines = [head, "|" + "---|" * 10]
    for p in paths:
        s = json.load(open(p))
        live = [t for t in s["targets"] if not t["silent"]]
        icmp = [t for t in live if t["probe"] == "icmp"]
        first = next((t for t in icmp if t["rank"] == RANK_ROUTER), None)
        hops = [t for t in icmp if RANK_HOP <= t["rank"] < RANK_DEST]
        isp = min(hops, key=lambda t: t["rank"]) if hops else None
        med = lambda ts: f"{statistics.median(t['loss_pct'] for t in ts):.2f}%" if ts else "-"
        dest_icmp = [t for t in icmp if t["rank"] == RANK_DEST]
        dest_tcp = [t for t in live if t["probe"] != "icmp" and t["rank"] == RANK_DEST]
        v = s.get("verdict")
        fmt = lambda t: f"{t['name']} {t['loss_pct']:.2f}%" if t else "-"
        lines.append(
            f"| {time.strftime('%a %Y-%m-%d %H:%M', time.localtime(s['start']))} "
            f"| {(s['end'] - s['start']) / 60:.0f} | {s['setup']}/{s['link']} "
            f"| {s['interval'] * 1000:.0f} ms | {fmt(first)} | {fmt(isp)} | {med(dest_icmp)} "
            f"| {med(dest_tcp)} | {(v['from'] + ' → ' + v['to']) if v else 'unclear'} "
            f"| {period_text(s['periodic']) if s.get('periodic') else '-'} |")
    out = "\n".join(lines)
    print(out)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
        print(f"\nSaved to {args.out}")


def loss_pattern(dests, stats, link):
    """One finding describing how the internet targets lose packets (bursts vs isolated)."""
    lossy = [t for t in dests if stats[t.name]["loss_pct"] >= 0.5 and stats[t.name]["bursts"]]
    if not lossy:
        return []
    bursts = [b for t in lossy for b in stats[t.name]["bursts"]]
    iv = stats[lossy[0].name]["interval"]
    short = max(1, int(0.3 / iv))
    pcts = [stats[t.name]["loss_pct"] for t in lossy]
    names = ", ".join(t.name for t in lossy)
    if sum(1 for b in bursts if b <= short) / len(bursts) >= 0.8:
        return [("!", f"{names} lose {min(pcts):.1f}–{max(pcts):.1f}% of packets, almost all as "
                 f"isolated losses ({fmt_dur(iv)}–{fmt_dur(short * iv)}), not outages: individual "
                 f"packets getting lost, from {loss_causes(link)}.")]
    return [("!", f"{names} lose {min(pcts):.1f}–{max(pcts):.1f}% of packets, including outages "
             f"up to {fmt_dur(max(bursts) * iv)}: short outages (link flaps, resets).")]


def error_correlation(tracker, samples, iface):
    """Do the interface's input-error increments line up with loss events?"""
    jumps = [t for (t0, a), (t, b) in zip(samples, samples[1:]) if b > a]
    if not jumps:
        return []
    losses = [e for e in tracker.events if e["kind"] == "loss" and e["seg"] != "ratelimit"]
    near = lambda t: any(-0.6 <= j - t <= 1.6 for j in jumps)
    hit = sum(1 for e in losses if near(e["t"]))
    # how often would a random moment "coincide" with an error just by chance?
    chance = sum(1 for t, _ in samples if near(t)) / len(samples)
    out = [("i", f"{iface} counted input errors in {len(jumps)} of {len(samples)} half-second "
            f"samples; {hit} of {len(losses)} loss events happened at the same time "
            f"(by chance alone: ~{chance * len(losses):.0f}).")]
    if not losses:
        return out
    rate = hit / len(losses)
    if chance >= 0.7:
        out.append(("i", f"Input errors on {iface} happen so often that they can't be matched to "
                    "individual losses. To rule out the adapter, compare with a run over another "
                    "adapter or Wi-Fi: if the loss stays the same, the adapter isn't the cause."))
    elif rate >= 0.5 and rate > chance + 0.25:
        out.append(("!", f"Most loss events coincide with input errors on {iface}: frames are "
                    "damaged or lost on the way into this computer. Swap the cable and the "
                    "Ethernet adapter before blaming the line."))
    elif losses:
        out.append(("i", f"Input errors on {iface} mostly don't coincide with the losses, so they "
                    "are probably frames this adapter discards anyway (e.g. other VLANs / "
                    "multicast) and not the cause."))
    return out


def binom_tail(n, k, p):
    """P(X >= k) for X ~ Binomial(n, p), in log space so large n doesn't overflow."""
    if k <= 0:
        return 1.0
    if p <= 0:
        return 0.0
    if p >= 1:
        return 1.0
    if k <= n * p:
        return 1.0      # at or below the expected count: not unusual at all
    lp, lq = math.log(p), math.log1p(-p)
    # above the mean the terms only shrink, so stop once they no longer matter
    first = math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1) + k * lp + (n - k) * lq
    total = 0.0
    for i in range(k, n + 1):
        x = math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq
        total += math.exp(x - first)
        if x - first < -40:
            break
    return min(1.0, math.exp(first) * total)


def period_scan(times, start, end, interval=0.05, max_period=300, masked=0.0):
    """Candidate loss intervals, most convincing first.

    `times` are the send times of rounds with a loss. For each whole-second period, find
    the phase window that the most cycles have a loss in, and how unlikely that many hits
    would be with random loss (`p`). Phases come from the epoch, so they match the wall clock.
    `masked`: share of the time whose losses were taken out (already explained by another
    interval), so the remaining ones happened in the rest of the time."""
    dur = end - start
    bursts = []
    for t in sorted(times):        # a drop spanning a few rounds counts once
        if not bursts or t - bursts[-1] > 0.3:
            bursts.append(t)
    if len(bursts) < 4 or dur < 60:
        return []
    # intervals under 5 s need fine sampling to see where in the cycle a loss falls
    periods = range(1 if interval <= 0.2 else 5, int(min(max_period, dur / 3)) + 1)
    rate = len(bursts) / (dur * (1 - masked))
    found = []
    tests = 0
    for P in periods:
        w = min(0.5, P / 8)         # the matching window shrinks for short intervals
        # chance a cycle has a loss in the window. Probes go out on a fixed grid, so a loss
        # can only fall on a probe moment, and a window placed on one covers up to w /
        # interval + 1 of them: count it as one probe interval wider (or a 100 ms grid
        # turns random loss into a "significant" 1 s pattern).
        p_cycle = 1 - math.exp(-rate * (w + interval))
        tests += min(P / w, len(bursts))   # windows tried: one per loss, at most P / w distinct
        # (phase in the cycle, cycle number); the copy shifted by one cycle lets a window
        # wrap around the end of the cycle
        ph = sorted((t % P, int(t // P)) for t in bursts)
        ext = ph + [(q + P, k - 1) for q, k in ph]
        # slide a window of width w over the phases, counting distinct cycles inside it
        inside, top, j = Counter(), None, 0
        for i, (p0, _) in enumerate(ph):
            while j < i + len(ph) and ext[j][0] - p0 <= w:
                inside[ext[j][1]] += 1
                j += 1
            if top is None or len(inside) > top[0]:
                qs = [q for q, _ in ext[i:j]]
                # spread of the hits: 10th to 90th percentile, so one stray loss doesn't count;
                # each lost probe stands for up to one probe interval of outage
                spread = qs[(len(qs) - 1) * 9 // 10] - qs[(len(qs) - 1) // 10] + interval
                top = (len(inside), statistics.median(qs) % P, spread)
            k = ext[i][1]
            inside[k] -= 1
            if not inside[k]:
                del inside[k]
        cycles = math.ceil(dur / P)
        hits = min(top[0], cycles)
        # binomial tail P(X >= hits): how likely is this many by chance?
        tail = binom_tail(cycles, hits, p_cycle)
        found.append({"period": P, "phase": top[1], "spread": top[2], "hits": hits, "cycles": cycles,
                      "expected": round(cycles * p_cycle, 1), "p": tail, "window": w})
    # Many intervals and positions in the cycle were tried and only the best is shown, so
    # correct for that (Bonferroni) by the number of windows tried.
    for c in found:
        c["p_adj"] = min(1.0, c["p"] * tests)
    return sorted(found, key=lambda c: c["p"])


def find_period(times, start, end, interval, max_period=300):
    """Do the losses recur at the same point of a fixed cycle (a timer somewhere)?"""
    found = period_scan(times, start, end, interval, max_period)
    best = found[0] if found else None
    if not best or significance(best) < 2:
        return None
    P, ph0, w = best["period"], best["phase"], best["window"]
    best["share"] = sum(1 for t in times
                        if abs((t - ph0 + P / 2) % P - P / 2) <= w / 2) / len(times)
    # wall-clock seconds (time zones are whole minutes, so epoch seconds mod 60 match)
    best["seconds"] = wall_seconds(best)
    best["start"] = start
    best["drift"] = phase_drift(best, sorted(times))
    return best


def wall_seconds(c):
    """Second(s) of the minute a candidate hits, if its period divides a minute."""
    P = c["period"]
    return sorted((c["phase"] + k * P) % 60 for k in range(60 // P)) if 60 % P == 0 else None


def moment_text(P, phase, start):
    """When in its cycle a timer hits, in words. Phases count from the epoch, so cycles that
    fit into a minute start on the full minute."""
    if P == 1:
        frac = f"{phase % 1:.2f}"[1:]       # ".27"
        return f"at :00{frac}, :01{frac}, :02{frac}, …"
    if 60 % P == 0 and P >= 30:
        return "at " + " and ".join(f":{(phase + k * P) % 60:05.2f}" for k in range(60 // P)) + " of every minute"
    if 60 % P == 0:
        return f"at :{phase % P:05.2f}, :{phase % P + P:05.2f}, :{phase % P + 2 * P:05.2f}, …"
    # doesn't fit evenly into a minute: name the first one by the clock
    if start is None:      # summary.json from an older version
        return f"at phase {phase:.2f} s"
    return f"first at {clock(start + (phase - start) % P, 2)}, then every {P} s"


def period_text(per):
    when = f", {moment_text(per['period'], per['phase'], per.get('start'))}"
    spread = f", losses within {per['spread'] * 1000:.0f} ms" if "spread" in per else ""
    if per.get("drift"):
        spread += f", the moment drifts {per['drift'] * 1000:+.0f} ms per hour"
    return (f"every {per['period']} s{when}{spread}: {per['hits']} of "
            f"{per['cycles']} cycles (expected by chance: ~{per['expected']:.0f})")


def segment_by_rate(targets, loss_pct, rounds, min_step=0.2, min_packets=8):
    """Find where the loss rate steps up and stays up for every target behind it (like mtr).

    Random per-packet loss on a shared segment rarely hits two destinations in the
    same round, so this is more reliable than counting per-round events. The step
    must be at least `min_packets` lost packets so a few random drops in a short
    run don't produce a confident answer.
    Returns (hop_before, hop_after, loss_before, loss_after, segment) or None.
    """
    min_step = max(min_step, 100 * min_packets / rounds) if rounds else 100
    silent = [t.rank for t in targets if loss_pct[t.name] >= 90]   # ignores this probe type
    targets = [t for t in targets if loss_pct[t.name] < 90]
    hops = sorted((t for t in targets if t.rank < RANK_DEST), key=lambda t: (t.rank, not t.port))
    dests = [t for t in targets if t.rank == RANK_DEST]
    chain = [(t.name, t.rank, loss_pct[t.name]) for t in hops]
    if dests:
        # median, not min: one destination (or protocol) with less loss shouldn't hide the step
        chain.append(("internet", RANK_DEST, statistics.median(loss_pct[t.name] for t in dests)))
    prev_name, prev_rank, prev_loss = "you", -1, 0.0
    for i, (name, rank, l) in enumerate(chain):
        if l - prev_loss >= min_step and all(x >= 0.5 * l for _, _, x in chain[i:]):
            # silent devices in between hide where exactly the segment starts
            if any(prev_rank < r < rank for r in silent):
                return prev_name, name, prev_loss, l, "unclear"
            return prev_name, name, prev_loss, l, segment_for(prev_rank, rank)
        prev_name, prev_rank, prev_loss = name, rank, l
    return None


def localize(tracker, targets, stats, interval, info=None):
    out = []
    info = {} if info is None else info
    loss = tracker.tally("loss")
    spikes = tracker.tally("spike")

    print("\n── Where it happens " + "─" * 42)
    for kind, tally, label in (("loss", loss, "loss events"), ("spike", spikes, "latency spikes")):
        if not tally:
            print(f"  {label}: none")
            continue
        print(f"  {label}:")
        for seg, cnt in tally.most_common():
            evs = [e for e in tracker.events if e["kind"] == kind and e["seg"] == seg]
            longest = max(e["rounds"] for e in evs) * interval
            print(f"    {cnt:5d}×  {SEGMENT_SHORT[seg]:<28}  longest {fmt_dur(longest)}")
    if loss:
        print("  (counted per probe round: random loss mostly hits one target per round, so a"
              "\n   lost packet often looks like \"single destination\" or \"several targets\""
              "\n   here; the loss rates per hop above and the verdict below are what count)")

    # Random per-packet loss on a shared segment rarely hits two destinations in the
    # same round, so per-round events alone undercount it. Primary verdict: where
    # does the loss rate step up and persist for every target behind it (like mtr)?
    dests = [t for t in targets if t.rank == RANK_DEST]
    seg_rate = segment_by_rate(targets, {k: v["loss_pct"] for k, v in stats.items()},
                               max(v["sent"] for v in stats.values()))
    shared = False
    if len(dests) >= 2:
        n = stats[dests[0].name]["sent"]
        a, b = (set(stats[t.name]["lost_seqs"]) for t in dests[:2])
        both = len(a & b)
        expected = len(a) * len(b) / n if n else 0
        shared = both >= 3 and both > 5 * expected
        info["shared"] = {"a": dests[0].name, "b": dests[1].name, "both": both,
                          "expected": round(expected, 2)}
        if shared:
            out.append(("!", f"{dests[0].name} and {dests[1].name} lost a packet in the same "
                        f"round {both}× (≈{expected:.1f}× expected by chance): the losses are real "
                        "and come from a shared part of the path, not from those hosts."))

    real = {k: v for k, v in loss.items() if k != "ratelimit"}
    total = sum(real.values())
    info["verdict"] = None
    if seg_rate:
        a, b, la, lb, top = seg_rate
        info["verdict"] = {"from": a, "to": b, "loss_before": round(la, 3),
                           "loss_after": round(lb, 3), "segment": top}
        out.append(("!", f"VERDICT: loss is {la:.2f}% up to {a} and {lb:.2f}% from {b} on, "
                    f"and stays that high for everything behind it, so packets are lost "
                    f"between {a} and {b}: {SEGMENT_TEXT[top]}."))
    elif shared and max(real, key=real.get, default=None) in ("onedest", "partial"):
        top = None
        out.append(("!", "VERDICT: the losses are real and shared by all destinations (see above), "
                    "but this run is too short to say at which hop they start. Keep it running."))
    elif total < 3:
        top = None
        out.append(("i", f"VERDICT: only {total} real loss event(s), too few to blame a segment. "
                    "Keep it running longer, ideally while the connection feels bad."))
    else:
        top = max(real, key=real.get)
        share = real[top] / total
        dest_loss = [stats[t.name]["loss_pct"] for t in dests]
        if top in ("onedest", "partial") and len(dest_loss) >= 2 and min(dest_loss) >= 0.2:
            # every destination loses packets, just rarely in the same round: that's
            # random loss on a shared path, not one misbehaving host
            top = None
            out.append(("i", "VERDICT: all internet destinations lose packets "
                        f"({min(dest_loss):.1f}–{max(dest_loss):.1f}%), but this run is too short "
                        "to say at which hop it starts. Keep it running longer."))
        else:
            out.append(("!", f"VERDICT: {real[top]} of {total} loss events ({share * 100:.0f}%) "
                        f"point to {SEGMENT_TEXT[top]}."))
    if top:
        out.append(("i", ADVICE[top]))
    if loss.get("ratelimit"):
        out.append(("i", f"{loss['ratelimit']} losses happened only on an intermediate hop while "
                    "everything behind it still answered. That hop just deprioritizes ICMP "
                    "aimed at itself, so ignore them. If it's a lot, try a bigger -i."))

    # where does a latency step first appear?
    order = sorted(targets, key=lambda t: t.rank)
    for t in order:
        if t.port:
            continue
        m = stats[t.name].get("modes", [])
        if len(m) > 1:
            out.append(("i", f"The two-level latency first shows up at {t.name} ({t.addr}), "
                        "so it's introduced on the segment just before that hop."))
            break

    r = next((stats[t.name] for t in targets if t.rank == RANK_ROUTER), {})
    if r.get("p50") is not None and (r["p50"] > 5 or r.get("p99", 0) > 30):
        out.append(("!", f"Router replies are slow for a local link (p50 {r['p50']:.1f} ms, p99 "
                    f"{r['p99']:.1f} ms; expect ~1-4 ms on a good link). Busy radio "
                    "(contention, power save, scans) or an overloaded router."))
    if spikes.get("local", 0) >= 3:
        loc = [e for e in tracker.events if e["kind"] == "spike" and e["seg"] == "local"]
        long_ = [e for e in loc if e["rounds"] * interval >= 1]
        if len(long_) >= 0.4 * len(loc):
            out.append(("!", "Local latency spikes often last a second or more (RTT climbing to "
                        "50-150 ms, then recovering). That's the Mac's radio going off-channel, "
                        "usually a Wi-Fi scan: Location Services, an open Wi-Fi menu, apps that "
                        "list networks, or AWDL."))
    return out


def cmd_analyze(args):
    findings = []
    for path in args.files:
        with open(path, errors="replace") as f:
            series = analyze_series(parse_ping_lines(f), args.interval)
        print_series(path, series)
        findings += findings_for(series, os.path.basename(path))
    if args.wifi:
        _, iface = default_route()
        if iface and detect_link(iface, None) == "wifi":
            findings += wifi_findings([wifi_snapshot(iface)])
    findings.append(("i", "A single-target log can't tell where the loss happens. "
                     "Run `./netdiag.py run` to probe every hop at once."))
    print_findings(findings)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze saved ping output")
    a.add_argument("files", nargs="+")
    a.add_argument("-i", "--interval", type=float, default=1.0, help="ping interval used (s)")
    a.add_argument("--no-wifi", dest="wifi", action="store_false", help="skip current Wi-Fi snapshot")
    a.set_defaults(func=cmd_analyze)
    r = sub.add_parser("run", help="live multi-hop test until Ctrl+C")
    r.add_argument("-i", "--interval", type=float, default=0.05,
                   help="seconds between probe rounds (default 0.05 = 20/s per target)")
    r.add_argument("-d", "--duration", type=int, default=0, help="stop after N seconds (default: run until Ctrl+C)")
    r.add_argument("--link", choices=["wifi", "ethernet"], help="skip auto-detection of the connection type")
    r.add_argument("--ont", help="IP of a separate ONT/modem between router and fiber "
                                 "(default: the home router is also the modem, e.g. a fiber box with built-in router)")
    r.add_argument("--hops", type=int, default=5,
                   help="trace this many hops towards the first host and probe them (default 5)")
    r.add_argument("--hosts", nargs="+", default=["1.1.1.1", "8.8.8.8"])
    r.add_argument("--no-tcp", dest="tcp", action="store_false",
                   help="don't add TCP handshake probes (port 80/443) to the ONT and internet hosts")
    r.add_argument("--out", default="netdiag-logs")
    r.set_defaults(func=cmd_run)
    sm = sub.add_parser("summarize", help="compare saved runs side by side")
    sm.add_argument("dirs", nargs="*", default=["netdiag-logs"])
    sm.add_argument("--out", default="netdiag-logs/summary.md", help="also save the table here")
    sm.set_defaults(func=cmd_summarize)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
