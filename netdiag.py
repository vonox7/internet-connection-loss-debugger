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
import atexit
import bisect
import concurrent.futures
import contextlib
import csv
import errno
import glob
import itertools
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
IPV6_HOPLIMIT, IPV6_TCLASS = getattr(socket, "IPV6_HOPLIMIT", 47), getattr(socket, "IPV6_TCLASS", 36)

# Path order of targets. Traced hop N gets rank RANK_HOP + N.
RANK_ROUTER, RANK_ONT, RANK_HOP, RANK_DEST = 0, 1, 10, 100
# A TCP probe answered only after a resend (by the server or by macOS): a packet was lost,
# but TCP recovered it. Stored in Target.rtt next to float (answered) and None (lost).
RESENT = "resent"
# well-known destinations, named in the dashboard
KNOWN_HOSTS = {"1.1.1.1": "Cloudflare", "8.8.8.8": "Google", "208.67.222.222": "OpenDNS",
               "185.15.58.224": "Wikipedia", "9.9.9.9": "Quad9"}


def is_lost(v):
    """A lost packet: no answer, or one that TCP had to resend."""
    return v is None or v is RESENT


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
    resent = sum(1 for v in samples.values() if v is RESENT)
    if resent:      # a TCP resend means a lost packet: count it as one, and say so apart
        samples = {s: None if v is RESENT else v for s, v in samples.items()}
    seqs = list(samples)
    rtts = [v for v in samples.values() if v is not None]
    lost = [s for s, v in samples.items() if v is None]
    n = len(seqs)
    r = {"sent": n, "recv": len(rtts), "lost": len(lost),
         "loss_pct": 100 * len(lost) / n if n else 0.0, "lost_seqs": lost, "resent": resent}
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
    if r.get("tcp"):
        n = r["sent"]
        print(f"  TCP       of the lost: {r['resent']} answered after a resend ({100 * r['resent'] / n:.2f}%), "
              f"{r['lost'] - r['resent']} never ({100 * (r['lost'] - r['resent']) / n:.2f}%)")
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


def clock_offset():
    """How far this Mac's clock is off (seconds, + = ahead), from time.apple.com; None if
    it can't be reached. The timer moments and their drift are measured on this clock."""
    try:
        out = subprocess.run(["sntp", "-t", "3", "time.apple.com"], capture_output=True,
                             text=True, timeout=10).stdout
        m = re.search(r"^([+-]\d+\.\d+) \+/- (\d+\.\d+)", out, re.M)
        # sntp prints how much to correct the clock by: the clock is off by the opposite
        return (-float(m.group(1)), float(m.group(2))) if m else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def iface_counters(iface):
    out = subprocess.run(["netstat", "-b", "-I", iface], capture_output=True, text=True).stdout.splitlines()
    if len(out) < 2:
        return None
    hdr = out[0].split()
    row = out[1].split()
    try:
        # rows may lack the Address column; count from the end
        get = lambda name: int(row[len(row) - (len(hdr) - hdr.index(name))])
        return {"ierrs": get("Ierrs"), "oerrs": get("Oerrs"), "coll": get("Coll"),
                "ibytes": get("Ibytes"), "obytes": get("Obytes")}
    except (ValueError, IndexError):
        return None


def trace_hops(dest, max_hops):
    """traceroute to dest. Returns (raw output, [(hop number, ip)]). Many servers don't
    answer traceroute's UDP packets at the end of the path: then it's redone with pings."""
    for proto in ("udp", "icmp"):
        out = subprocess.run(["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(max_hops),
                              "-P", proto, dest], capture_output=True, text=True, timeout=90).stdout
        hops = []
        for line in out.splitlines():
            m = re.match(r"\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                hops.append((int(m.group(1)), m.group(2)))
        if hops and hops[-1][1] == dest:
            break
    return out, hops


# priority markings (DSCP, in the TOS byte) of the extra probes: what each one asks for
MARKINGS = (("EF", 0xB8, "voice, top priority"), ("AF41", 0x88, "video, high priority"),
            ("CS1", 0x20, "background, lowest priority"))
V6_HOSTS = {"2606:4700:4700::1111": "Cloudflare", "2001:4860:4860::8888": "Google"}


def has_ipv6():
    """Is there an IPv6 route to the internet? (connecting a UDP socket sends nothing)"""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect((next(iter(V6_HOSTS)), 53))
            return not s.getsockname()[0].startswith(("fe80", "fd", "fc"))
    except OSError:
        return False


def trace6_hops(dest, max_hops=6):
    out = subprocess.run(["traceroute6", "-n", "-q", "1", "-w", "1", "-m", str(max_hops), dest],
                         capture_output=True, text=True, timeout=60).stdout
    return [(int(m.group(1)), m.group(2)) for m in
            (re.match(r"\s*(\d+)\s+([0-9a-f:]+:[0-9a-f:]*)\s", line) for line in out.splitlines()) if m]


def extra_probes(targets, first_isp):
    """Probes that answer side questions, next to the normal ones (see Target.extra):
    big packets (bit errors on a line hit big packets more often than small ones; an
    overloaded queue drops both alike), priority markings (does the ISP's traffic management
    treat them differently?) and IPv6 (a different path through the ISP: no carrier-grade NAT)."""
    out = []
    hop = next((t for t in targets if RANK_HOP <= t.rank < RANK_DEST and not t.port), None)
    dest = next((t for t in targets if t.rank == RANK_DEST and not t.port), None)
    for base in (hop, dest):
        if base:
            out.append(Target(f"{base.name}·1400B", base.addr, base.rank, base.hop, size=1400,
                              extra=True, label="big: 1400 bytes"))
    if hop:
        for mark, tos, what in MARKINGS:
            out.append(Target(f"{hop.name}·{mark}", hop.addr, hop.rank, hop.hop, tos=tos, extra=True,
                              label=f"{mark}: {what}"))
    if has_ipv6():
        hops = trace6_hops(next(iter(V6_HOSTS)))
        isp = next((ip for n, ip in hops if n == first_isp), None)
        if isp:
            out.append(Target("v6-isp", isp, RANK_HOP + first_isp, first_isp, v6=True, extra=True,
                              label="IPv6 ISP hop"))
        for addr, name in V6_HOSTS.items():
            out.append(Target(f"v6-{name.lower()}", addr, RANK_DEST, None, v6=True, extra=True,
                              label=f"IPv6 {name}"))
    return out


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
        return None
    ping_ok = answers_echo([t.addr for t in local])
    blocked = [(t, err) for t in local if t.addr in ping_ok
               for ok, err in [python_reaches(t.addr)] if not ok]
    if not blocked:
        return None
    app = os.environ.get("TERM_PROGRAM", "your terminal app").replace("Apple_Terminal", "Terminal")
    return (f"ping reaches {', '.join(t.addr for t, _ in blocked)}, but this program can't "
            f"({blocked[0][1]}): macOS is blocking local-network access for {app}. Allow it in "
            f"System Settings → Privacy & Security → Local Network, restart {app} and run again "
            "(until then those hops show 100% loss and are left out of the analysis)")


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
    def __init__(self, name, addr, rank, hop=None, port=None, size=None, tos=0, v6=False,
                 extra=False, label=None):
        self.name, self.addr, self.rank, self.hop = name, addr, rank, hop
        self.port = port       # None = ICMP echo, otherwise TCP connect to this port
        self.size = size       # ICMP: IP packet size in bytes (default: small)
        self.tos = tos         # IP TOS byte (priority marking) of the probes
        self.v6 = v6           # ICMPv6 instead of ICMP
        # extra probes (packet size, marking, IPv6) are compared in the analysis, but stay
        # out of the loss localization, the events and the interval scan
        self.extra = extra
        self.label = label     # name shown in the dashboard
        self.ttl = None        # TTL / hop limit of the last reply; changes = route changes
        self.ttl_changes = []  # (wall time, new TTL)
        self.reply_tos = Counter()   # TOS byte of the replies -> count
        self.resend_ms = {}    # TCP: round -> handshake time of a resent one (direction)
        self.rtt = []          # index = round; float ms, None = lost, RESENT, ... = pending
        self.late = 0          # replies that came after the timeout
        self.lost_at = 0       # wall time the last probe was declared lost (dashboard flash)
        self.fastest = None    # fastest TCP handshake so far, ms


class Prober:
    """Probes every target once per round: ICMP echo over an unprivileged ICMP socket,
    or a TCP handshake for targets with a port (measures what real traffic sees, even
    where ICMP is deprioritized)."""

    def __init__(self, targets, interval, timeout=1.0, tcp_timeout=1.9):
        self.targets, self.interval, self.timeout = targets, interval, timeout
        # a TCP probe waits for one resend (macOS resends the SYN after 1 s)
        self.tcp_timeout = tcp_timeout if any(t.port for t in targets) else timeout
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
        self.sock6 = None
        if any(t.v6 for t in targets):
            self.sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)
            self.sock6.settimeout(0.2)
            self.sock6.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMP, 1)
            self.sock6.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            for opt in (socket.IPV6_RECVHOPLIMIT, getattr(socket, "IPV6_RECVTCLASS", 35)):
                with contextlib.suppress(OSError):
                    self.sock6.setsockopt(socket.IPPROTO_IPV6, opt, 1)
        self.tos = 0           # TOS currently set on the ICMP socket
        # the probes' own traffic in kbit/s, each direction: ICMP request and reply (IP +
        # ICMP header + payload, or the big size); TCP SYN / RST out, SYN-ACK in (~60 bytes)
        per_round = sum(60 if t.port else (t.size or (48 if t.v6 else 20) + 8 + 25) for t in targets)
        self.probe_kbps = per_round * 8 / 1000 / interval
        # measurement quality per minute: [minute start, worst send delay ms, worst read
        # delay ms, replies read too late]
        self.quality = []
        self.expired = {}      # (ident, wire_seq) -> wall send time, of probes declared lost
        self.misread = []      # wall times of replies that came in time but were read too late
        self.send_t = []       # wall-clock send time per round
        self.pending = {}      # (ident, wire_seq) -> (round, perf_counter at send)
        self.tcp_pending = {}  # socket -> (target, round, perf_counter at send)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.start_t = None
        self.slept = None      # (wall time asleep, wall time awake) if the Mac slept
        self.traffic = []      # (time, bytes in, bytes out, input errors) of this Mac, per second
        self.status_runs = 0
        self.clock_checks = []     # (time, offset s, uncertainty s) of this Mac's clock
        self.keep = None       # rounds still valid after a sleep

    def _quality(self, now):
        """This minute's row of the measurement quality log."""
        m = now // 60 * 60
        if not self.quality or self.quality[-1][0] != m:
            self.quality.append([m, 0.0, 0.0, 0])
        return self.quality[-1]

    def run(self):
        threading.Thread(target=self._recv_loop, daemon=True).start()
        if self.sock6:
            threading.Thread(target=self._recv_loop, args=(True,), daemon=True).start()
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
            if wait < 0:
                q = self._quality(time.time())
                q[1] = max(q[1], -wait * 1000)
            if self.send_t and (time.time() - self.send_t[-1]) - (time.perf_counter() - last) > 5:
                # The Mac slept (lid closed, empty battery): the wall clock jumped while
                # perf_counter stood still. Rounds around the sleep would count as lost,
                # so keep only those that finished well before it, and stop the test.
                with self.lock:
                    asleep = self.send_t[-1]
                    self.slept = (asleep, time.time())
                    self.keep = bisect.bisect_left(self.send_t, asleep - self.tcp_timeout - 2)
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
                    # a big probe: pad to the IP packet size (20 bytes IP + 8 ICMP header)
                    data = payload.ljust(t.size - 28, b"\0") if t.size else payload
                    if t.v6:     # the kernel fills in the ICMPv6 checksum
                        pkt, sock, dest = (struct.pack("!BBHHH", 128, 0, 0, ident, seq) + data,
                                           self.sock6, (t.addr, 0, 0, 0))
                    else:
                        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
                        pkt, sock, dest = (struct.pack("!BBHHH", 8, 0, icmp_checksum(hdr + data),
                                                       ident, seq) + data, self.sock, (t.addr, 0))
                        if t.tos != self.tos:
                            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, t.tos)
                            self.tos = t.tos
                    self.pending[(ident, seq)] = (n, time.time())    # right before sending
                    try:
                        sock.sendto(pkt, dest)
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
        if t.tos:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, t.tos)
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
                    # SYN after its 1 s timeout, i.e. the first SYN or SYN-ACK was lost. Some
                    # servers (Google) resend a lost SYN-ACK after only ~300 ms: an answer
                    # 250 ms slower than this target's fastest one is such a resend, too.
                    # Both count as RESENT; no answer even after that is lost.
                    ms = (now - t0) * 1000
                    if err not in (0, errno.ECONNREFUSED):
                        t.rtt[n], t.lost_at = None, time.time()
                    elif ms < 900 and ms < (t.fastest or ms) + 250:
                        t.fastest = min(t.fastest or ms, ms)
                        t.rtt[n] = ms
                    else:
                        t.rtt[n], t.lost_at = RESENT, time.time()
                        t.resend_ms[n] = ms      # when: tells whose resend it was
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
        cutoff = n - int(self.tcp_timeout / self.interval) - 1
        for s, (t, rnd, _) in list(self.tcp_pending.items()):
            if rnd <= cutoff:
                del self.tcp_pending[s]
                t.rtt[rnd], t.lost_at = None, time.time()
                s.close()

    def _recv_loop(self, v6=False):
        sock = self.sock6 if v6 else self.sock
        while not self.stop.is_set():
            try:
                data, anc, _, _ = sock.recvmsg(4096, 256)
            except socket.timeout:
                continue
            except OSError:
                continue
            now = read = time.time()
            ttl = tos = None
            for lvl, typ, d in anc:
                if lvl == socket.SOL_SOCKET and typ == SCM_TIMESTAMP and len(d) >= 12:
                    sec, usec = struct.unpack("qi", d[:12])
                    now = sec + usec / 1e6
                elif lvl == socket.IPPROTO_IPV6 and typ == IPV6_HOPLIMIT and d:
                    ttl = d[0]
                elif lvl == socket.IPPROTO_IPV6 and typ == IPV6_TCLASS and d:
                    tos = d[0]
            # IPv4 replies come with their IP header: TOS and TTL are in there
            ihl = (data[0] & 0x0F) * 4 if not v6 and data and data[0] >> 4 == 4 else 0
            if ihl:
                tos, ttl = data[1], data[8]
            if len(data) < ihl + 8:
                continue
            typ, _, _, ident, seq = struct.unpack("!BBHHH", data[ihl:ihl + 8])
            t = self.by_ident.get(ident)
            if typ != (129 if v6 else 0) or t is None:
                continue
            q = self._quality(read)
            q[2] = max(q[2], (read - now) * 1000)
            if ttl is not None and ttl != t.ttl:
                if t.ttl is not None:
                    t.ttl_changes.append((now, ttl))
                t.ttl = ttl
            if tos is not None:
                t.reply_tos[tos] += 1
            with self.lock:
                p = self.pending.pop((ident, seq), None)
                if p is None:
                    sent = self.expired.pop((ident, seq), None)
                    if sent is not None and now - sent < self.timeout:
                        # answered in time, but this Mac was too busy to read it before the
                        # timeout: the tool's fault, not the network's
                        self.misread.append(sent)
                        self._quality(read)[3] += 1
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
            done = max(0, n - int(max(self.timeout, self.tcp_timeout) / self.interval) - 1)
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
        self.resent = Counter()     # target name -> TCP probes answered only after a resend
        self.hist = {t.name: {} for t in prober.targets}    # see update()
        self.tz = time.localtime().tm_gmtoff      # buckets start on the local 10 minutes
        # per round with a loss on the ISP side (after the home router / ONT): (send time,
        # share of those targets) for ICMP lost, TCP lost and TCP resent
        self.isp_loss = {"icmp": [], "tcp_lost": [], "tcp_resent": []}
        self.periodic, self._period_at = None, 0
        self.scroll, self.seen, self.page = 0, 0, 1    # dashboard: events list position
        self.show_help = False      # dashboard: the explanation of the interval table (h key)
        self.view = 0               # dashboard: index into VIEWS (1-4, ←/→, Tab)
        self.out_dir = ""

    def update(self):
        upto = self.p.done_rounds()
        # the extra probes (packet size, marking, IPv6) only get counted, they stay out of
        # the events and the loss analysis
        targets = [t for t in self.p.targets if not t.extra]
        for n in range(self.done, upto):
            if n in (40, 200) or (n and n % 1000 == 0):
                # a device that ignores this probe type would look like a permanent outage
                w = min(n, 200)
                silent = {t.name for t in targets
                          if sum(1 for v in t.rtt[n - w:n] if v is None) >= 0.9 * w}
                # if nothing answered, that's an outage, not devices ignoring the probe type
                if len(silent) < len(targets):
                    self.dead = silent
            # per 10 minutes and target: [rounds, lost, resent, resent quickly (by the server),
            # RTTs in 0.5 ms bins], for the Trends view
            b = int((self.p.send_t[n] + self.tz) // TREND_S)
            for t in self.p.targets:
                h = self.hist[t.name].get(b)
                if h is None:
                    h = self.hist[t.name][b] = [0, 0, 0, 0, Counter()]
                h[0] += 1
                v = t.rtt[n]
                if v is None:
                    self.lost[t.name] += 1
                    h[1] += 1
                elif v is RESENT:
                    self.resent[t.name] += 1
                    h[2] += 1
                    h[3] += t.resend_ms.get(n, 1000) < 900
                elif isinstance(v, float):
                    h[4][int(v * 2)] += 1          # 0.5 ms bins
            alive = [t for t in targets if t.name not in self.dead]
            lost = [t for t in alive if is_lost(t.rtt[n])]
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
                # ISP side = everything after the home router / ONT
                icmp = [t for t in alive if t.rank > RANK_ONT and not t.port]
                tcp = [t for t in alive if t.rank > RANK_ONT and t.port]
                for key, group, test in (("icmp", icmp, lambda v: v is None),
                                         ("tcp_lost", tcp, lambda v: v is None),
                                         ("tcp_resent", tcp, lambda v: v is RESENT)):
                    bad = sum(1 for t in group if test(t.rtt[n]))
                    if bad:
                        self.isp_loss[key].append((self.p.send_t[n], bad / len(group)))
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
    kind = f"tcp:{t.port}" if t.port else "icmpv6" if t.v6 else "icmp"
    return kind + (f", {t.size} bytes" if t.size else "") + (f", TOS 0x{t.tos:02x}" if t.tos else "")


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
    that second is above the target's median; loss = how many probes got lost (1-9, # for 10+),
    yellow if TCP resent all of them."""
    ping, loss = [], []
    for c in range(n_cols):
        a = end - (n_cols - c) * per_col
        b = a + per_col
        if b <= 0:
            ping.append((" ", None))
            loss.append((" ", None))
            continue
        vals = t.rtt[max(0, a):b]
        lost = sum(1 for v in vals if is_lost(v))
        hard = any(v is None for v in vals)
        loss.append((str(lost) if lost < 10 else "#", "1;31" if hard else WARN) if lost else (" ", None))
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
    "interval in the range shown and every moment within it is tried. \"when\" = at which "
    "moment of the cycle the losses happen, as seconds of the clock: \"at :24.19 and :54.19 of "
    "every minute\" = 12:00:24.19, 12:00:54.19, 12:01:24.19, …; intervals that don't fit evenly "
    "into a minute show the clock time of their first loss. \"spread\" = how tightly the losses "
    "cluster around that moment; \"drift\" = how fast that moment moves (a device clock running "
    "slightly fast or slow; measured from 30 min); \"seen\" = in how many cycles there was a "
    "loss at that moment, \"expected\" = how many cycles would have a loss at that moment "
    "anyway, if the same number of losses happened at random times. \"Chance it's just luck\" "
    "says how rarely random loss alone would produce the best pattern found (taking into "
    "account that all intervals were searched): 1 in 10 000 or rarer is statistically "
    "significant, 1 in 1 000 possibly significant (a longer run will tell). The whole run lists "
    "those plus the best guesses up to 4 rows; the last minutes only those, or the best guess.")


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
    c["drift_fit"] = (mt, md, slope)       # where the moment is at any time (see at_timer)
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
            tracker._views = busy.result()
            tracker._intervals = (tracker._intervals_at, _interval_blocks(tracker._views, use_color))
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
    tracker._views = scan_views(*job)
    tracker._intervals = (now, _interval_blocks(tracker._views, use_color))
    return tracker._intervals[1]


_POOL = None


def _ignore_sigint():
    signal.signal(signal.SIGINT, signal.SIG_IGN)     # Ctrl+C is the main process's business


def scan_views(loss_t, first, end, interval, window_s, guesses=5):
    """Loss intervals for the whole run and, once it's long enough, the last `window_s`
    seconds (None: whole run only): [(label, start, end, interval, losses, candidates)].
    Candidates: all (possibly) significant ones, filled up to `guesses` with the best others."""
    views = [("whole run", first)]
    if window_s and end - first > 2 * window_s:   # the moment of a timer can drift
        views.append((f"last {window_s // 60} min", end - window_s))
    out = []
    for label, start in views:
        times = [t for t in loss_t if t >= start]
        n = len([t for i, t in enumerate(times) if not i or t - times[i - 1] > 0.3])
        found, masked = [], 0.0
        while len(found) < 8:
            cands = period_scan(times, start, end, interval, masked=masked)
            if not cands or (len(found) >= guesses and not significance(cands[0])):
                break       # the best guesses, plus any further (possibly) significant ones
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
            summary = ("nothing statistically significant (best guesses below)"
                       if label == "whole run" else "nothing statistically significant (best guess below)")
        lo, hi = 1 if interval <= 0.2 else 5, int(min(300, (end - start) / 3))
        checked = f"intervals {lo}–{hi} s checked" if hi >= lo and n >= 4 else "nothing checked yet"
        out = [color(f"{label}: {n} losses in {(end - start) / 60:.1f} min", "1", use_color)
               + color(f" · {checked} · ", GREY, use_color) + summary]
        # the (possibly) significant ones; the whole run fills up to 4 rows with the best
        # guesses, the last minutes show just the best guess without any
        if label == "whole run":
            keep = []
            for c in found:
                if significance(c) or len(keep) < 4:
                    keep.append(c)
            found = keep
        else:
            found = [c for c in found if significance(c)] or found[:1]
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


# blue: loss at a regular timer, in the loss-over-time chart (the terminal's own blue).
TIMER_COLOR = "34"
# the bold red used everywhere, as a background: terminals show bold red as bright red
RED_BG = "101"


def at_timer(c, t):
    """Is a loss at time `t` one of timer candidate `c`'s (within its window around its
    moment, the same one the interval table uses, following the drift if there is one)?"""
    P = c["period"]
    d = (t - c["phase"] + P / 2) % P - P / 2
    if c.get("drift") and c.get("drift_fit"):
        mt, md, slope = c["drift_fit"]
        d -= md + slope * (t - mt)
    return abs(d) <= c["window"]


def loss_by_time(losses, start, end, interval, timers, size):
    """Loss per wall-clock bucket of `size` seconds: [bucket start, probe rounds, lost probes
    (in rounds), of those per timer], from (time, share of the ISP-side probes lost) per round.
    A round at several timers' moments counts for the first."""
    off = time.localtime(start).tm_gmtoff        # buckets start on the local full hour
    first = (start + off) // size * size - off
    buckets = []
    b = first
    while b < end:
        buckets.append([b, max(1.0, (min(b + size, end) - max(b, start)) / interval), 0,
                        [0] * len(timers)])
        b += size
    for t, share in losses:
        i = int((t - first) // size)
        if t < start or not 0 <= i < len(buckets):
            continue
        row = buckets[i]
        row[2] += share
        k = next((k for k, c in enumerate(timers) if at_timer(c, t)), None)
        if k is not None:
            row[3][k] += share
    return buckets


def bucket_size(start, end, width):
    """Seconds per chart column: 10 min, coarser if that many columns don't fit `width`."""
    for size in (600, 1200, 1800, 3600):
        if (end - start) / size + 2 <= width - 9:
            return size
    return 3600


def bar_chart(cols, start, use_color, height, axis, bottom, top, top_bg):
    """Stacked bars, one per time bucket: cols = [(bucket start, total %, bottom part %)].
    The bottom part in color `bottom`, the rest in `top`; where both meet inside a cell, the
    bottom part is drawn on a `top_bg` background."""
    peak = max(c[1] for c in cols) or 0.01
    rows = []
    for r in range(height - 1, -1, -1):
        row = ""
        for _, p, bp in cols:
            fill = min(8, max(0, max(1 if p else 0, round(p / peak * height * 8)) - 8 * r))
            bfill = min(8, max(0, round(bp / peak * height * 8) - 8 * r))
            if fill == 8 and 0 < bfill < 8 and use_color:
                row += color(SPARK[bfill], f"{bottom};{top_bg}", True)
            elif fill:
                row += color(SPARK[fill], bottom if 2 * bfill >= fill else top, use_color)
            else:
                row += " "
        label = f"{peak:5.2f}% ┤" if r == height - 1 else "       │"
        rows.append(color(label, GREY, use_color) + row)
    if axis:
        rows.append(color("       └" + "─" * len(cols), GREY, use_color))
    # clock times under the columns that start a full hour, and the start if there's room
    marks, free = [" "] * (len(cols) + 8), 0
    hours = [i for i, c in enumerate(cols) if c[0] >= start and time.localtime(c[0]).tm_min == 0]
    if not hours or hours[0] >= 6:
        hours.insert(0, 0)
    for i in hours:
        if i >= free:
            marks[8 + i:8 + i + 5] = time.strftime("%H:%M", time.localtime(max(cols[i][0], start)))
            free = i + 6
    rows.append(color("".join(marks).rstrip(), GREY, use_color))
    return rows


TCP_RESENT_BG = "48;5;178"      # WARN as a background


def loss_blocks(isp, start, end, interval, timers, size, use_color, live):
    """ICMP and TCP loss of the ISP-side targets: [(title, chart columns, chart colors,
    legend, [(row label, legend color, label color, [% per hour])], hour starts)].
    ICMP is split into the regular timers and the rest, TCP into resent and lost."""
    sig = [c for c in timers if significance(c) == 2]
    # live also shows the possibly significant timers (a longer run will tell)
    timers = [c for c in timers if significance(c) >= (1 if live else 2)]
    pct = lambda n, rounds: 100 * n / rounds
    out = []
    if isp["icmp"] or not (isp["tcp_lost"] or isp["tcp_resent"]):
        b = loss_by_time(isp["icmp"], start, end, interval, sig, size)
        h = loss_by_time(isp["icmp"], start, end, interval, timers, 3600)
        rows = [("loss", "", "1", [pct(x[2], x[1]) for x in h]),
                ("random", "1;31", "", [pct(x[2] - sum(x[3]), x[1]) for x in h])]
        for k, c in enumerate(timers):
            ok = significance(c) == 2
            rows.append((f"every {c['period']} s" + ("" if ok or not live else " (maybe)"),
                         TIMER_COLOR if ok else "", "" if ok else WARN, [pct(x[3][k], x[1]) for x in h]))
        names = ", ".join(f"every {c['period']} s" for c in sig)
        legend = (color("█", "1;31", use_color) + " random loss   " + (
            color("█", TIMER_COLOR, use_color) + f" at a regular timer ({names})" if sig else
            color("no statistically significant timer found", GREY, use_color)))
        out.append(("ICMP (ping)", [(x[0], pct(x[2], x[1]), pct(sum(x[3]), x[1])) for x in b],
                    (TIMER_COLOR, "1;31", RED_BG), legend, rows, [x[0] for x in h]))
    if isp["tcp_lost"] or isp["tcp_resent"]:
        lb = loss_by_time(isp["tcp_lost"], start, end, interval, [], size)
        rb = loss_by_time(isp["tcp_resent"], start, end, interval, [], size)
        lh = loss_by_time(isp["tcp_lost"], start, end, interval, [], 3600)
        rh = loss_by_time(isp["tcp_resent"], start, end, interval, [], 3600)
        rows = [("loss", "", "1", [pct(l[2] + r[2], l[1]) for l, r in zip(lh, rh)]),
                ("resent", WARN, "", [pct(r[2], r[1]) for r in rh]),
                ("lost", "1;31", "", [pct(l[2], l[1]) for l in lh])]
        legend = (color("█", WARN, use_color) + " resent (answered after a resend)   "
                  + color("█", "1;31", use_color) + " lost (no answer even after a resend)")
        out.append(("TCP (handshakes)", [(l[0], pct(l[2] + r[2], l[1]), pct(l[2], l[1]))
                                         for l, r in zip(lb, rb)],
                    ("1;31", WARN, TCP_RESENT_BG), legend, rows, [x[0] for x in lh]))
    return out


def loss_over_time(isp, start, end, interval, timers, cols, use_color, live):
    """The loss-over-time section: per protocol a chart and the loss per hour (live: next
    to each other, hours as columns; report: below each other, hours as rows)."""
    what = "average loss of the targets after your router / ONT (the ISP side)"
    if live:
        # both protocols side by side if they fit, else below each other
        for width in ((cols - 1) // 2 - 2, cols - 1):
            size = bucket_size(start, end, width)
            blocks = [_live_block(b, start, width, use_color)
                      for b in loss_blocks(isp, start, end, interval, timers, size, use_color, True)]
            if width == cols - 1 or all(max(map(vis_len, b)) <= width for b in blocks):
                break
        out = [headline(f"Loss over time · {what}, {size // 60} min per column", cols, use_color)]
        if width < cols - 1 and len(blocks) == 2:
            w = width + 4
            return out + [a + " " * (w - vis_len(a)) + b for a, b in itertools.zip_longest(
                *blocks, fillvalue="")]
        for i, b in enumerate(blocks):
            out += ([""] if i else []) + b
        return out
    size = bucket_size(start, end, cols)
    out = [color(f"  {what}, {size // 60} min per column", HELP, use_color)]
    for title, chart, colors, legend, rows, hours in loss_blocks(
            isp, start, end, interval, timers, size, use_color, False):
        out += ["", "  " + title] + bar_chart(chart, start, use_color, 5, True, *colors)
        out += ["        " + legend, ""]
        out.append(color("  hour " + "".join(f"{r[0]:>{max(8, len(r[0]) + 2)}}" for r in rows),
                         GREY, use_color))
        for k, h in enumerate(hours):
            out.append(f"  {time.strftime('%H:%M', time.localtime(max(h, start)))}" + "".join(
                f"{r[3][k]:>{max(8, len(r[0]) + 2) - 1}.2f}%" for r in rows))
    return out


def _live_block(block, start, width, use_color):
    """One protocol: title, chart and loss per hour (hours as columns) side by side, or
    stacked if both don't fit `width`. The row labels double as the chart's legend."""
    title, chart, colors, _, rows, hours = block
    chart = bar_chart(chart, start, use_color, 5, False, *colors)
    lw = max(len(r[0]) for r in rows) + 4

    def table(n):
        out = [color(" " * lw + "".join(f"{time.strftime('%H:%M', time.localtime(max(h, start))):>7}"
                                        for h in hours[-n:]), GREY, use_color)]
        for label, block, code, vals in rows:
            head = (color("█ ", block, use_color) if block else "  ") + label
            out.append(color(head + " " * (lw - len(label) - 2), code, use_color and bool(code))
                       + "".join(f"{v:6.2f}%" for v in vals[-n:]))
        return out

    cw = max(map(vis_len, chart)) + 4
    head = [color(title, "1", use_color)]
    if cw + lw + 7 * len(hours) <= width:     # everything fits next to the chart
        right = table(len(hours))
        return head + [a + " " * (cw - vis_len(a)) + b for a, b in itertools.zip_longest(
            chart, right, fillvalue="")]
    return head + chart + table(max(1, (width - lw) // 7))


def differs(a, n, b, m):
    """Are a of n and b of m clearly different shares (two-proportion z-test, |z| > 3)?"""
    if not n or not m:
        return False
    p = (a + b) / (n + m)
    if p in (0, 1):
        return False
    return abs(a / n - b / m) / math.sqrt(p * (1 - p) * (1 / n + 1 / m)) > 3


def comparisons(prober, tracker):
    """Side questions, answered from the extra probes and logs: [(topic, text)]."""
    done = tracker.done
    if not done:
        return []
    by = {t.name: t for t in prober.targets}
    lost = lambda t: tracker.lost[t.name] + tracker.resent[t.name]
    pc = lambda t: f"{100 * lost(t) / done:.2f}%"
    out = []

    # direction: a server that resends its SYN-ACK faster than macOS resends the SYN tells
    # which one got lost
    for t in prober.targets:
        if not t.port or t.extra:
            continue
        fast = sum(1 for ms in t.resend_ms.values() if ms < 900)
        slow = len(t.resend_ms) - fast
        if fast >= 3:
            out.append(("Direction", f"{t.name}: ISP → you {100 * fast / done:.2f}%, you → ISP "
                        f"{100 * slow / done:.2f}% (the server resends its lost reply after "
                        f"~0.3 s, macOS a lost request after ~1 s)"))
    if not any(o[0] == "Direction" for o in out) and any(t.port for t in prober.targets):
        out.append(("Direction", "unknown: no server here resent faster than macOS yet"))

    def pairs(topic, base, variants, same, diff):
        if not base or not variants:
            return
        rows = [(name, t) for name, t in variants if t]
        verdict = [name for name, t in rows if differs(lost(base), done, lost(t), done)]
        text = f"{base.name}: " + " · ".join(f"{name} {pc(t)}" for name, t in rows)
        out.append((topic, text + f"  → {diff + ': ' + ', '.join(verdict) if verdict else 'no clear difference so far: ' + same}"))

    for t in prober.targets:
        big = by.get(f"{t.name}·1400B")
        if big:
            pairs("Packet size", t, [("small", t), ("1400 B", big)],
                  "points to a queue (overload), not to bit errors",
                  "big packets differ (bit errors on a line hit big packets more)")
        marks = [(m, by.get(f"{t.name}·{m}")) for m in ("EF", "AF41", "CS1")]
        if any(v for _, v in marks):
            pairs("Priority marking", t, [("none", t)] + marks,
                  "all markings treated alike", "treated differently")
    v6 = [(by.get(a), by.get(b)) for a, b in (
        (next((t.name for t in prober.targets if RANK_HOP <= t.rank < RANK_DEST and not t.port
               and not t.extra), None), "v6-isp"), ("1.1.1.1", "v6-cloudflare"), ("8.8.8.8", "v6-google"))]
    for t4, t6 in v6:
        if t4 and t6:
            pairs("IPv4 vs IPv6", t4, [("IPv4", t4), ("IPv6", t6)],
                  "not caused by the IPv4 NAT", "IPv4 and IPv6 differ")

    # this Mac's own traffic: was the line idle when packets got lost?
    tr = prober.traffic
    if len(tr) > 2:
        rates = [(b[0], (b[1] - a[1] + b[2] - a[2]) * 8 / 1000 / max(0.1, b[0] - a[0]))
                 for a, b in zip(tr, tr[1:])]
        # minus the probes' own traffic
        own = prober.probe_kbps
        rates = [(t, max(0.0, r - 2 * own)) for t, r in rates]
        down = max(0.0, (tr[-1][1] - tr[0][1]) * 8 / 1000 / max(1, tr[-1][0] - tr[0][0]) - own)
        up = max(0.0, (tr[-1][2] - tr[0][2]) * 8 / 1000 / max(1, tr[-1][0] - tr[0][0]) - own)
        busy_s = idle_s = busy_l = idle_l = 0
        lt, j = tracker.loss_t, 0
        for (t0, _), (t1, rate) in zip([(tr[0][0], 0)] + rates, rates):
            while j < len(lt) and lt[j] < t0:
                j += 1
            k = j
            while k < len(lt) and lt[k] < t1:
                k += 1
            if rate > 1000:
                busy_s, busy_l = busy_s + t1 - t0, busy_l + k - j
            else:
                idle_s, idle_l = idle_s + t1 - t0, idle_l + k - j
            j = k
        iv = prober.interval
        part = lambda l, sec: f"{100 * l * iv / sec:.2f}%" if sec >= 60 else "- (under 1 min)"
        out.append(("Your own traffic", f"average {down:.0f} kbit/s down, {up:.0f} kbit/s up "
                    f"(without the probes' {own:.0f}) · "
                    f"rounds with a loss while it was quiet {part(idle_l, idle_s)}, while busy "
                    f"(> 1 Mbit/s, {busy_s / 60:.0f} min) {part(busy_l, busy_s)}"))

    changes = [(t, w) for t in prober.targets for w, _ in t.ttl_changes]
    if getattr(prober, "replay", False):
        changes = None
    routes = changes is not None and f"{len(changes)} TTL changes" + (
        f" (last: {max(changes, key=lambda c: c[1])[0].name} at {clock(max(c[1] for c in changes))})"
        if changes else "") + " (the reply's TTL counts the routers on the way: a change = a new route)"
    if changes is not None:
        out.append(("Routes", routes))
    order = ["Direction", "Packet size", "Priority marking", "IPv4 vs IPv6"]
    out.sort(key=lambda o: order.index(o[0]) if o[0] in order else len(order))
    if prober.clock_checks:
        offs = [f"{o * 1000:+.0f} ms (±{u * 1000:.0f})" for _, o, u in prober.clock_checks]
        worst = max(abs(o) for _, o, _ in prober.clock_checks)
        out.append(("Mac clock", f"off from time.apple.com by {' at the start, '.join(offs)}"
                    + (" at the end" if len(offs) > 1 else "") + (
                        ": timer moments and their drift are measured right" if worst < 0.05 else
                        ": off by more than 50 ms, timer moments are shifted by that much")))
    q = prober.quality
    if q:
        out.append(("Measurement", f"worst send delay {max(r[1] for r in q):.0f} ms, worst read "
                    f"delay {max(r[2] for r in q):.0f} ms, {sum(r[3] for r in q)} replies read "
                    "too late (the Mac kept up if these stay small)"))
    return out


TREND_S = 600      # seconds per trend bucket


def trends(prober, tracker, link_samples=()):
    """What changed over the run: [(group title, unit, [(label, {bucket: (value, num, den)})])].
    Buckets are 10 local minutes; num/den (counts) let start and end be tested against each
    other where the value is a share."""
    by = {t.name: t for t in prober.targets}
    hist = tracker.hist
    keys = sorted(set().union(*(h.keys() for h in hist.values()))) if hist else []
    if not keys:
        return []
    share = lambda num, den: {b: (100 * num(b) / den(b) if den(b) else 0.0, num(b), den(b)) for b in keys}
    h = lambda t, b, i: hist[t.name].get(b, [0, 0, 0, 0, None])[i]
    lost = lambda t: share(lambda b: h(t, b, 1) + h(t, b, 2), lambda b: h(t, b, 0))

    def p50(t):
        out = {}
        for b in keys:
            c = hist[t.name].get(b, [0, 0, 0, 0, Counter()])[4]
            n, acc = sum(c.values()), 0
            for half in sorted(c):
                acc += c[half]
                if acc >= n / 2:
                    out[b] = (half / 2 + 0.25, None, None)
                    break
        return out

    main = [t for t in prober.targets if not t.extra and not t.port and t.rank > RANK_ONT]
    hop = next((t for t in main if t.rank < RANK_DEST), None)
    dests = [t for t in main if t.rank == RANK_DEST]
    name = lambda t: KNOWN_HOSTS.get(t.addr, t.name) if t.rank == RANK_DEST else f"ISP first hop ({t.name})"
    groups = []
    groups.append(("Loss per destination (each leaves the ISP through another exit)", "%",
                   [(name(t), lost(t)) for t in ([hop] if hop else []) + dests]))
    tcp = [t for t in prober.targets if t.port and not t.extra and t.rank == RANK_DEST]
    if tcp:
        tot = lambda i: (lambda b: sum(h(t, b, i) for t in tcp))
        if getattr(prober, "resent_known", True):
            groups.append(("TCP to the destinations", "%", [
                ("resent (TCP recovered it)", share(tot(2), tot(0))),
                ("lost (even after a resend)", share(tot(1), tot(0)))]))
        else:       # a run from before resends were told apart
            groups.append(("TCP to the destinations", "%", [
                ("lost or resent", share(lambda b: tot(1)(b) + tot(2)(b), tot(0)))]))
    groups.append(("Latency, median", "ms", [(name(t), p50(t)) for t in ([hop] if hop else []) + dests]))
    quick = [t for t in tcp if sum(x[3] for x in hist[t.name].values()) >= 3]
    if quick:
        n = lambda b: sum(h(t, b, 0) for t in quick)
        groups.append((f"Direction ({', '.join(KNOWN_HOSTS.get(t.addr, t.name) for t in quick)}: "
                       "server resends quickly)", "%", [
            ("ISP → you", share(lambda b: sum(h(t, b, 3) for t in quick), n)),
            ("you → ISP", share(lambda b: sum(h(t, b, 2) - h(t, b, 3) for t in quick), n))]))
    rows = []
    for t in main:
        if f"{t.name}·1400B" in by:
            rows += [(f"{name(t)}, small", lost(t)), (f"{name(t)}, 1400 bytes", lost(by[f"{t.name}·1400B"]))]
    if rows:
        groups.append(("Packet size", "%", rows))
    if hop and f"{hop.name}·EF" in by:
        groups.append(("Priority marking (ISP first hop)", "%", [("unmarked", lost(hop))] + [
            (f"{m}: {what}", lost(by[f"{hop.name}·{m}"])) for m, _, what in MARKINGS
            if f"{hop.name}·{m}" in by]))
    rows = []
    for t4, t6 in ((hop, by.get("v6-isp")), (by.get("1.1.1.1"), by.get("v6-cloudflare")),
                   (by.get("8.8.8.8"), by.get("v6-google"))):
        if t4 and t6:
            rows += [(f"{name(t4)}, IPv4", lost(t4)), (f"{name(t4)}, IPv6", lost(t6))]
    if rows:
        groups.append(("IPv4 vs IPv6", "%", rows))

    def per_bucket(samples, value):
        """{bucket: value of the samples in it}, from (time, ...) samples."""
        out = {}
        for x in samples:
            out.setdefault(int((x[0] + tracker.tz) // TREND_S), []).append(x)
        return {b: (value(v), None, None) for b, v in out.items() if v}

    tr = prober.traffic
    if len(tr) > 2:
        own = prober.probe_kbps
        rate = lambda i: per_bucket(
            [(b[0], b[i] - a[i], b[0] - a[0]) for a, b in zip(tr, tr[1:])],
            lambda v: max(0.0, sum(x[1] for x in v) * 8 / 1000 / max(1, sum(x[2] for x in v)) - own))
        groups.append(("Your own traffic (without the probes')", "kbit/s",
                       [("down", rate(1)), ("up", rate(2))]))
    if link_samples:
        groups.append(("Wi-Fi", "dBm", [("signal", per_bucket(
            [(x["t"], x["rssi"]) for x in link_samples], lambda v: statistics.median(x[1] for x in v)))]))
    changes = [(w,) for t in prober.targets for w, _ in t.ttl_changes]
    if not getattr(prober, "replay", False):
        groups.append(("Routes", "", [("TTL changes", {**{b: (0, None, None) for b in keys},
                                                       **per_bucket(changes, len)})]))
    if prober.quality:
        groups.append(("Measurement", "ms", [("worst read delay", per_bucket(
            [(m + 30, b) for m, _, b, _ in prober.quality if m], lambda v: max(x[1] for x in v)))]))
    loss = ("Loss per destination", "TCP to the destinations", "Latency", "Direction")
    out = []
    for title, unit, rows in groups:
        rows = [(label, vals) for label, vals in rows if vals]
        if rows:        # a topic without any data yet is left out
            out.append((title, unit, rows, "loss" if title.startswith(loss) else "tests"))
    return out


SERIES_COLORS = ("36", "35", "34", "32", "33", "37")   # the series of a trend chart
SERIES_GLYPHS = ("█", "▓", "▒", "░", "#", "+")          # the same without colors (report)


def trend_lines(prober, tracker, cols, use_color, link_samples=(), part=None):
    """The Trends views / report section: per group one chart over the run in the style of
    the loss-over-time chart, its series as grouped bars (one column each per time slot,
    same scale), and below it per series the first and the last hour, the lowest and the
    highest hour, and whether start and end differ. Two groups side by side if they fit.
    `part`: only the "loss" or the "tests" groups."""
    groups = [g[:3] for g in trends(prober, tracker, link_samples) if part in (None, g[3])]
    if not groups:
        return []
    keys = sorted({b for _, _, rows in groups for _, vals in rows for b in vals})
    hours = {}
    for b in keys:
        hours.setdefault(b * TREND_S // 3600, []).append(b)
    span = min(len(keys), 6)       # start / end: the first and the last hour (or less)
    first, last = keys[:span], keys[-span:]

    def agg(vals, bs):
        """Value of a set of buckets: counts summed if there are any, else the mean."""
        got = [vals[b] for b in bs if b in vals]
        if not got:
            return None, 0, 0
        if got[0][2] is not None:
            num, den = sum(g[1] for g in got), sum(g[2] for g in got)
            return (100 * num / den if den else 0.0), num, den
        return statistics.mean(g[0] for g in got), None, None

    # two charts side by side if each still gets a useful width
    bw = (cols - 4) // 2 if (cols - 4) // 2 >= 90 else cols - 1
    blocks = []
    for title, unit, rows in groups:
        n = len(rows)
        fmt = lambda v: ("-" if v is None else f"{v:.2f}" if unit == "%" else
                         f"{v:.1f}" if unit == "ms" else f"{v:.0f}")
        # time slots: 10 min, or merged until every slot's bars fit (n bars + a gap each)
        k = next((k for k in (1, 2, 3, 6, 12, 18, 24, 36, 72) if (len(keys) // k + 2) * (n + 1)
                  <= bw - 9), 144)
        # slots on the clock (10 / 20 / 30 min, whole hours), so hours start a slot
        slots = [list(g) for _, g in itertools.groupby(keys, key=lambda b: b // k)]
        vals = [[agg(v, sl)[0] for sl in slots] for _, v in rows]
        flat = [v for row in vals for v in row if v is not None] or [0]
        lo, hi = (min(flat), max(flat)) if unit == "dBm" else (0, max(flat) or 1e-9)
        height = 5 if n > 1 else 3      # a single series needs less room
        chart = []
        for r in range(height - 1, -1, -1):
            line = ""
            for si in range(len(slots)):
                for ri in range(n):
                    v = vals[ri][si]
                    lvl = 0 if v is None else max(1 if v > lo or unit == "dBm" else 0,
                                                  round((v - lo) / ((hi - lo) or 1) * height * 8))
                    fill = min(8, max(0, lvl - 8 * r))
                    if not fill:
                        line += " "
                    elif use_color:
                        line += color(SPARK[fill], SERIES_COLORS[ri % 6], True)
                    else:      # no colors: a shade per series, cells at least half full
                        line += SERIES_GLYPHS[ri % 6] if fill >= 4 else " "
                line += " "
            top = f"{fmt(hi)}{unit if unit == '%' else ''}"
            label = f"{top:>6} ┤" if r == height - 1 else (f"{fmt(lo):>6} ┤" if r == 0 and unit == "dBm"
                                                            else "       │")
            chart.append(color(label, GREY, use_color) + line)
        marks, free = [" "] * (len(slots) * (n + 1) + 8), 0
        for si, sl in enumerate(slots):
            hour = next((b for b in sl if b * TREND_S % 3600 == 0), None)
            if si * (n + 1) >= free and (si == 0 or hour is not None):
                lt = time.gmtime((hour if hour is not None else sl[0]) * TREND_S)  # local, see tz
                marks[8 + si * (n + 1):8 + si * (n + 1) + 5] = time.strftime("%H:%M", lt)
                free = si * (n + 1) + 6
        chart.append(color("".join(marks).rstrip(), GREY, use_color))
        # the series: legend and numbers
        lw = min(max(len(label) for label, _ in rows) + 2, max(12, bw - 66))
        table = [color(f"  {'':<{lw}}{'start':>8}{'end':>8}{'lowest':>13}{'highest':>13}  change "
                       "start → end", GREY, use_color)]
        for ri, (label, v) in enumerate(rows):
            s_, sn, sd = agg(v, first)
            e_, en, ed = agg(v, last)
            per_hour = [(x, hr) for hr in sorted(hours) for x in [agg(v, hours[hr])[0]] if x is not None]
            low = min(per_hour, default=None)
            high = max(per_hour, default=None)
            at = lambda x: f"{fmt(x[0])} {time.strftime('%H:00', time.gmtime(x[1] * 3600))}" if x else "-"
            if len(keys) < 2 * span or s_ is None or e_ is None:
                change = "-"
            elif sd is not None:
                change = (("↑ " if e_ > s_ else "↓ ") + (f"{e_ / s_:.1f}×" if s_ else "from 0")
                          if differs(sn, sd, en, ed) else "no clear change")
            else:
                change = (("↑ " if e_ > s_ else "↓ ") + f"{e_ / s_:.1f}×" if s_ and abs(e_ / s_ - 1) > 0.2
                          else "about the same")
            key = (color("█", SERIES_COLORS[ri % 6], True) if use_color else SERIES_GLYPHS[ri % 6])
            table.append(f"{key} {label[:lw]:<{lw}}{fmt(s_):>8}{fmt(e_):>8}{at(low):>13}{at(high):>13}  "
                         + color(change, "1" if change.startswith(("↑", "↓")) else GREY, use_color))
        head = color(title, "1", use_color) + (color(f" · {unit}", GREY, use_color) if unit else "")
        blocks.append([head] + chart + table)

    out = []
    if bw < cols - 1:          # two per row
        for a, b in itertools.zip_longest(blocks[0::2], blocks[1::2], fillvalue=[]):
            out += [""] + [x + " " * (bw + 3 - vis_len(x)) + y
                           for x, y in itertools.zip_longest(a, b, fillvalue="")]
    else:
        for b in blocks:
            out += [""] + b
    return out[1:]


def clock(t, decimals=1):
    return time.strftime("%H:%M:%S", time.localtime(t)) + f".{int(t * 10 ** decimals) % 10 ** decimals:0{decimals}d}"


def headline(title, cols, use_color):
    return color(f"── {title} " + "─" * max(0, cols - len(title) - 5), "1", use_color)


def event_line(e, interval, use_color, timers=()):
    """One event; a loss at the moment of a (statistically significant) timer says so."""
    ts = clock(e["t"])
    dur = fmt_dur(e["rounds"] * interval)
    if e["kind"] == "loss":
        timer = next((c for c in timers if at_timer(c, e["t"])), None)
        tag = color(f"  ({timer['period']} s timer)", TIMER_COLOR, use_color) if timer else ""
        return f"{ts}  {color('LOSS ', '1;31', use_color)}  {dur:>7}  {e['desc']}{tag}"
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
    views = getattr(tracker, "_views", None)
    timers = [c for c in views[0][5] if significance(c) == 2] if views else []
    out += [event_line(e, interval, use_color, timers) for e in shown]
    return out


def read_keys(tracker, stop):
    """Arrow / page keys scroll the events list (terminal in cbreak mode; Ctrl+C still works)."""
    fd = sys.stdin.fileno()
    keys = {b"\x1b[A": 1, b"k": 1, b"\x1b[B": -1, b"j": -1, b"\x1b[5~": "pg", b"\x1b[6~": "-pg",
            b"\x1b[H": "home", b"\x1b[1~": "home", b"g": "home",
            b"\x1b[F": "end", b"\x1b[4~": "end", b"G": "end", b"h": "help", b"?": "help",
            b"1": "v0", b"2": "v1", b"3": "v2", b"4": "v3", b"5": "v4", b"6": "v5", b"\t": "tab", b"\x1b[C": "tab", b"\x1b[D": "back"}
    while not stop.is_set():
        if not select.select([fd], [], [], 0.2)[0]:
            continue
        k = keys.get(os.read(fd, 16))
        if k == "pg":
            k = tracker.page
        elif k == "-pg":
            k = -tracker.page
        if k == "help":
            tracker.show_help = not tracker.show_help
        elif k in ("v0", "v1", "v2", "v3", "v4", "v5"):
            tracker.view = int(k[1])
        elif k == "tab":
            tracker.view = (tracker.view + 1) % len(VIEWS)
        elif k == "back":
            tracker.view = (tracker.view - 1) % len(VIEWS)
        elif k == "home":
            tracker.scroll = len(tracker.events)
        elif k == "end":
            tracker.scroll = 0
        elif k:
            tracker.scroll = max(0, tracker.scroll + k)


# what each view answers: now · when · what kind of loss · can the measurement be trusted
VIEWS = ("Live", "Timeline", "Tests", "Trends", "Test trends", "Raw")

GROUPS = (
    ("Direction", "a lost TCP reply is resent by the server, a lost request by macOS (after "
     "~1 s). Servers that resend sooner (Google: ~0.3 s) show which way packets get lost"),
    ("Packet size", "bit errors on a line hit big packets more often than small ones; an "
     "overloaded queue drops both alike"),
    ("Priority marking", "packets can ask for priority with a marking; the ISP's first hop copies "
     "it into its reply, so it counts both ways. Different loss = the ISP's traffic management "
     "treats them differently"),
    ("IPv4 vs IPv6", "IPv6 takes another path through the ISP (no carrier-grade NAT)"),
    ("Your own traffic", "was this Mac busy when packets got lost? (the probes' own traffic "
     "doesn't count)"),
)


def cached_comparisons(prober, tracker):
    """comparisons(), redone at most every 10 s."""
    c = getattr(tracker, "_comp", None)
    if not c or time.time() - c[0] >= 10:
        c = tracker._comp = (time.time(), comparisons(prober, tracker))
    return c[1]


def detail_groups(prober, tracker, cols, use_color):
    """The extra probes for the Details view, grouped by question, each next to the normal
    probe it's compared with, with an explanation and the current verdict."""
    by = {t.name: t for t in prober.targets}
    main = [t for t in prober.targets if not t.extra and not t.port]
    verdicts = cached_comparisons(prober, tracker)
    groups = {title: [] for title, _ in GROUPS}
    for t in prober.targets:
        if t.port and not t.extra:
            # the same snapshot as the verdict above it
            fast = any(topic == "Direction" and text.startswith(t.name + ":") for topic, text in verdicts)
            groups["Direction"].append((t, f"{KNOWN_HOSTS.get(t.addr, t.addr)}: " + (
                "resends quickly, direction known" if fast else "resends after ~1 s, like macOS")))
    for t in main:
        if f"{t.name}·1400B" in by:
            groups["Packet size"] += [(t, "small: 53 bytes"), by[f"{t.name}·1400B"]]
        marks = [by[f"{t.name}·{m}"] for m, _, _ in MARKINGS if f"{t.name}·{m}" in by]
        if marks:
            groups["Priority marking"] += [(t, "unmarked")] + marks
    hop = next((t for t in main if RANK_HOP <= t.rank < RANK_DEST), None)
    v6 = {hop.name: "v6-isp"} if hop else {}
    v6.update({"1.1.1.1": "v6-cloudflare", "8.8.8.8": "v6-google"})
    for name, other in v6.items():
        if name in by and other in by:
            groups["IPv4 vs IPv6"] += [(by[name], f"IPv4: {by[name].label or KNOWN_HOSTS.get(by[name].addr, name)}"),
                                       by[other]]
    out = []
    for title, why in GROUPS:
        if not groups[title] and not any(topic == title for topic, _ in verdicts):
            continue
        head = wrap(f"{title} · {why}", cols - 2, "  ").split("\n")
        out += ["", color(title, "1", use_color) + color(head[0][len(title):], HELP, use_color)]
        out += [color(l, HELP, use_color) for l in head[1:]]
        for topic, text in verdicts:
            if topic == title:
                out += [color(l, "1", use_color) for l in
                        ("  → " + wrap(text, cols - 6, "    ")).split("\n")]
        out += groups[title]
    return out


def probe_table(prober, tracker, entries, title, cols, use_color, compact=False):
    """Per target: loss, latency and the per-second timeline (two rows each). An entry is a
    Target, (Target, label for its second row), or a line of text (a group heading).
    Compact: one row each, with the label in front and only the losses in the timeline."""
    done = tracker.done
    rows = [e if isinstance(e, (tuple, str)) else (e, None) for e in entries]
    targets = [e[0] for e in rows if not isinstance(e, str)]
    label = lambda t: f"{t.addr}:{t.port}" if t.port else t.addr
    name_of = lambda t, l2: l2 or t.label or (KNOWN_HOSTS.get(t.addr, t.name) if t.rank == RANK_DEST
                                             else t.name)
    aw = max(len(label(t)) for t in targets) + 2
    nw = max(len(name_of(*e)) for e in rows if not isinstance(e, str)) + 2 if compact else 0
    left_w = nw + aw + 37                # (name,) address, loss / resent / last / p50 / p95
    spark_w = max(10, cols - left_w - 4)
    per_col = max(1, round(1 / prober.interval))     # one column = one second
    spark_end = done // per_col * per_col   # only complete seconds: shifts once per second
    if compact:
        lines = [headline(title, cols, use_color),
                 f"{'':<{nw}}{'address':<{aw}}{'loss':>8}{'resent':>8}{'last':>7}{'p50':>7}"
                 f"{'p95':>7}   last {spark_w}s · " + color("digit", "1;31", use_color)
                 + " = lost/s, " + color("yellow", WARN, use_color) + " = all resent by TCP"]
    else:
        lines = [headline(title, cols, use_color),
             f"{'address':<{aw}}{'loss':>8}{'resent':>8}{'last':>7}{'p50':>7}"
             f"{'p95':>7}   last {spark_w}s · bar = ping above p50 (+5/10 ms, "
             + color(f"█ spike +{SPIKE_MS}", WARN, use_color) + ") · "
             + color("digit", "1;31", use_color) + " = lost/s, " + color("yellow", WARN, use_color)
             + " = all resent by TCP"]
    pcts = tracker._pcts[1]
    for entry in rows:
        if isinstance(entry, str):
            lines.append(entry)
            continue
        t, label2 = entry
        lost = tracker.lost[t.name]
        last = next((t.rtt[i] for i in range(done - 1, max(-1, done - 200), -1)
                     if isinstance(t.rtt[i], float)), None)
        p50, p95 = pcts.get(t.name, (None, None))
        f = lambda v: f"{v:7.1f}" if v is not None else "      -"
        loss = 100 * lost / done if done else 0
        ls = f"{loss:7.2f}%"
        # TCP: answered only after a resend (a packet was lost, TCP recovered it)
        rs = f"{100 * tracker.resent[t.name] / done if done else 0:7.2f}%" if t.port else " " * 8
        rest = f"{f(last)}{f(p50)}{f(p95)}"
        # compact: what the probe tests first (it matters), how it's measured (address) in grey
        left = (f"{name_of(t, label2):<{nw}}" + color(f"{label(t):<{aw}}", GREY, use_color) if compact
                else f"{label(t):<{aw}}")
        if time.time() - t.lost_at < 0.15:
            # flash the row the moment a probe is declared lost (redrawn 10×/s)
            left = color(left + ls + rs + rest, "1;97;41", use_color)
        else:
            left += (color(ls, "1;31", use_color) if loss >= 0.5 else ls) + rs + rest
        ping, lossc = spark_cells(t, spark_end, spark_w, per_col, p50)
        paint = lambda cells: "".join(color(ch, c, use_color) if c else ch for ch, c in cells)
        if compact:      # one row: the losses, a faint dot for seconds without
            lines.append(f"{left}   " + "".join(
                color(ch, c, use_color) if c else color("·" if p[0] != " " else " ", GREY, use_color)
                for (ch, c), p in zip(lossc, ping)))
            continue
        lines.append(f"{left}   {paint(ping)}")
        # loss row right under its ping row; stays empty while nothing is lost
        name = name_of(t, label2)
        name = f"{name[:left_w - 8]:<{left_w - 6}}"     # up to the "lost/s" label
        lines.append(color(name, GREY, use_color)
                     + color("lost/s", GREY, use_color) + "   " + paint(lossc))
    return lines


def render(prober, tracker, link_desc, wifi_now, started, use_color):
    """Draw the dashboard, full screen (on the alternate screen, from its top left)."""
    cols, term_rows = shutil.get_terminal_size((100, 30))
    done = tracker.done
    targets = prober.targets
    el = time.time() - started
    lines = []
    top = (color("netdiag", "1", use_color) +
           f"  {link_desc}  ·  {f'{int(el // 60)}m{int(el % 60):02d}s':>7}  ·  "
           f"{done:>7} rounds @ {prober.interval * 1000:.0f} ms  ·  Ctrl+C stops")
    wifi = ""
    if wifi_now:       # Wi-Fi link state, right-aligned on the same line
        w = wifi_now[-1]
        wifi = (f"Wi-Fi ch {w['channel']} · {w['rssi']} dBm · SNR {w['rssi'] - w['noise']} dB · "
                f"{w['rate']:.0f} Mbps")
    # the views as tabs, centered in the top line if there's room, else on a line of their own
    tabs = (" ".join(color(f" {i + 1} {name} ", "1;7" if tracker.view == i else HELP, use_color)
                     for i, name in enumerate(VIEWS))
            + color(f"  ← → or 1–{len(VIEWS)}", GREY, use_color))
    pos = max((cols - vis_len(tabs)) // 2, vis_len(top) + 3)   # centered, or right of the text
    if pos + vis_len(tabs) + 2 + len(wifi) <= cols - 1:
        top += " " * (pos - vis_len(top)) + tabs
        lines.append(top + " " * max(2, cols - 1 - vis_len(top) - len(wifi)) + wifi)
    else:
        lines.append(top + " " * max(2, cols - 1 - vis_len(top) - len(wifi)) + wifi)
        lines.append(tabs)
    # percentiles of the recent replies, refreshed every 5 s: sorting them on every frame
    # would eat the CPU time the probe threads need on long runs
    per_col = max(1, round(1 / prober.interval))
    cache = getattr(tracker, "_pcts", None)
    if not cache or done - cache[0] >= 5 * per_col or done < cache[0]:
        tracker._pcts = (done, {})
        for t in targets:
            nums = sorted(v for v in t.rtt[max(0, done - 20000):done] if isinstance(v, float))
            tracker._pcts[1][t.name] = (pct(nums, 50), pct(nums, 95)) if nums else (None, None)
    # the interval scan keeps running in the background whatever view is shown
    blocks = interval_blocks(prober, tracker, use_color)

    if tracker.view == 0:
        lines += probe_table(prober, tracker, [t for t in targets if not t.extra], "Probes", cols,
                             use_color)
        # newest events at the bottom, as many as fit
        lines.append("")
        lines += events_view(tracker, prober.interval, cols, term_rows - 1 - len(lines), use_color)
    elif tracker.view == 1:
        views = getattr(tracker, "_views", None)
        cache = getattr(tracker, "_over_time", None)
        if done and (not cache or time.time() - cache[0] >= 10 or cache[1] is not views
                     or cache[2] != cols):
            timers = views[0][5] if views else []
            cache = tracker._over_time = (time.time(), views, cols, loss_over_time(
                tracker.isp_loss, prober.send_t[0], prober.send_t[done - 1], prober.interval,
                timers, cols, use_color, True))
        if cache:
            lines += cache[3] + [""]
        if getattr(tracker, "_intervals_busy", None):
            status = "recalculating…"
        else:
            age = time.time() - tracker._intervals[0]
            status = (f"updated {age:.0f} s ago, next in "
                      f"{max(0, tracker._intervals_every - age):.0f} s")
        lines.append(headline(f"Regular loss intervals · {status} · h = "
                              + ("hide help" if tracker.show_help else "help"), cols, use_color))
        if tracker.show_help:
            lines += [color(l, HELP, use_color) for l in wrap(INTERVAL_HELP, cols - 2, "").split("\n")]
        w = max(map(vis_len, blocks[0])) + 6
        if len(blocks) == 2 and cols - 1 >= w + max(map(vis_len, blocks[1])):  # side by side
            for a, b in itertools.zip_longest(*blocks, fillvalue=""):
                lines.append(a + " " * (w - vis_len(a)) + b)
        else:
            for i, b in enumerate(blocks):
                lines += ([""] if i else []) + b
    elif tracker.view == 2:
        lines += probe_table(prober, tracker, detail_groups(prober, tracker, cols, use_color),
                             "Tests: what kind of loss is it? Each extra probe is next to the "
                             "normal one it's compared with" + ("" if any(t.extra for t in targets)
                                                                else " (none: --no-extra)"),
                             cols, use_color, compact=True)
    elif tracker.view in (3, 4):
        part = "loss" if tracker.view == 3 else "tests"
        cache = getattr(tracker, "_trends", None)
        if not cache or time.time() - cache[0] >= 10 or cache[1:3] != (cols, part):
            cache = tracker._trends = (time.time(), cols, part, trend_lines(
                prober, tracker, cols, use_color, wifi_now, part))
        lines.append(headline("Trends: what changed over the run, and what didn't" if part == "loss"
                              else "Test trends: how the tests changed over the run", cols, use_color))
        lines += cache[3] or ["  (after the first probe rounds)"]
    else:
        verdicts = dict(cached_comparisons(prober, tracker))
        lines.append(headline("Routes and markings of the replies", cols, use_color))
        if "Routes" in verdicts:
            lines.append(color("  → " + verdicts["Routes"], "1", use_color))
        for t in targets:
            if t.port:
                continue
            tos = ", ".join(f"0x{k:02x} {100 * v / max(1, sum(t.reply_tos.values())):.0f}%"
                            for k, v in t.reply_tos.most_common(2))
            change = (f"changed {len(t.ttl_changes)}×, last {clock(t.ttl_changes[-1][0])}"
                      if t.ttl_changes else "unchanged")
            lines.append(f"  {t.name:<22} TTL {t.ttl if t.ttl is not None else '-':>3} {change:<34}"
                         f"reply marking {tos or '-'}")
        lines += ["", headline("This Mac", cols, use_color)]
        tr = prober.traffic
        if len(tr) > 2:
            a, b = tr[max(0, len(tr) - 11)], tr[-1]
            sec = max(1, b[0] - a[0])
            own = prober.probe_kbps
            lines.append(f"  own traffic, last 10 s: {max(0, (b[1] - a[1]) * 8 / 1000 / sec - own):.0f} kbit/s "
                         f"down, {max(0, (b[2] - a[2]) * 8 / 1000 / sec - own):.0f} kbit/s up (without "
                         f"the probes' {own:.0f}) · interface input errors during the test: {b[3] - tr[0][3]}")
        if "Measurement" in verdicts:
            lines.append(color("  → whole run: " + verdicts["Measurement"], "1", use_color))
        if "Mac clock" in verdicts:
            lines.append(color("  → clock " + verdicts["Mac clock"], "1", use_color))
        q = prober.quality[-5:]
        if q:
            lines.append(f"  measurement, last 5 min: worst send delay {max(r[1] for r in q):.0f} ms, "
                         f"worst read delay {max(r[2] for r in q):.0f} ms, "
                         f"{sum(r[3] for r in q)} replies read too late")
        if prober.status_runs:
            lines.append(f"  --status-cmd ran {prober.status_runs}× (status.txt)")
        lines.append(f"  everything is logged to {tracker.out_dir}/ during the run")
    # exactly the screen: one line less would leave the old frame's last line, one more scrolls
    lines = lines[:term_rows]
    sys.stdout.write("\x1b[H" + "\x1b[K\r\n".join(fit(l, cols - 1) for l in lines) + "\x1b[K\x1b[J")
    sys.stdout.flush()


# ---------------------------------------------------------------- run

class Startup:
    """The startup screen: each step with … while it runs and ✓ (or ⚠) with its result. On a
    terminal it's drawn full screen, on the alternate screen the dashboard then takes over
    (like top or less); the finished list is printed again afterwards, so it stays in the
    scrollback. Without a terminal, finished steps are just printed."""

    def __init__(self, tty):
        self.tty, self.rows, self.full = tty, [], False
        if tty:
            self.full = True
            sys.stdout.write("\x1b[?1049h\x1b[?25l")    # alternate screen, cursor hidden
            atexit.register(self.leave)         # also on Ctrl+C or a crash during startup
        self.draw()

    def leave(self):
        """Back to the normal screen, as it was before the run."""
        if self.full:
            self.full = False
            sys.stdout.write("\x1b[?25h\x1b[?1049l")
            sys.stdout.flush()

    def step(self, text):
        self.rows.append(["…", text, ""])
        self.draw()

    def done(self, result="", mark="✓"):
        self.rows[-1][0], self.rows[-1][2] = mark, result
        self.draw()
        if not self.tty:
            print(self.line(self.rows[-1], False))

    def note(self, text, mark=""):
        """An extra line under the current step (a skipped hop, a warning)."""
        self.rows.append([mark, "  " + text, ""])
        self.draw()
        if not self.tty:
            print(self.line(self.rows[-1], False))

    def line(self, r, use_color):
        mark, text, result = r
        code = {"✓": "1;32", "⚠": WARN, "…": GREY}.get(mark)
        return (f"  {color(mark, code, use_color and bool(code)) if mark else ' '} {text}"
                + (color(f" · {result}", GREY if mark == "✓" else "", use_color and mark == "✓")
                   if result else ""))

    def text(self):
        return [self.line(r, False) for r in self.rows]

    def draw(self):
        if not self.full:
            return
        cols, rows = shutil.get_terminal_size((100, 30))
        out = ["", color("  netdiag", "1", True) + color("  getting ready…", GREY, True), ""]
        out += [self.line(r, True) for r in self.rows]
        out = out[-(rows - 1):]
        sys.stdout.write("\x1b[H" + "\x1b[K\r\n".join(fit(l, cols - 1) for l in out) + "\x1b[K\x1b[J")
        sys.stdout.flush()


def cmd_run(args):
    gw, iface = default_route()
    if not iface:
        sys.exit("No default route. Are you connected?")
    iface = physical_iface(iface)
    link = detect_link(iface, args.link)
    tty = sys.stdout.isatty()
    su = Startup(tty)
    su.step("Detecting the connection")
    port = hardware_ports().get(iface, iface)
    link_label = "Wi-Fi" if link == "wifi" else "Ethernet/LAN"
    su.done(f"{link_label} on {iface} ({port}), router {gw}")

    ont = args.ont
    # Direct mode: this machine is plugged straight into the ONT (no home router), so
    # the ONT is on-link and the default gateway is already the ISP's first router.
    direct = bool(ont) and on_link(ont)
    if ont and not direct and is_router_itself(ont):
        su.note(f"{ont} answers as hop 1, so it's an address of the router itself, not an ONT: "
                "ignoring --ont", "⚠")
        ont = None
    targets = []
    if direct:
        SEGMENT_TEXT.update(DIRECT_ONT_TEXT)
        SEGMENT_SHORT.update(DIRECT_ONT_SHORT)
        ADVICE.update(DIRECT_ONT_ADVICE)
        targets.append(Target("ont", ont, RANK_ROUTER))
        su.note(f"setup: this Mac → ONT {ont} (directly attached) → fiber → ISP gateway {gw}")
    elif gw:
        targets.append(Target("home-router", gw, RANK_ROUTER, hop=1))
    if direct:
        pass
    elif ont:
        SEGMENT_TEXT.update(SEPARATE_ONT_TEXT)
        SEGMENT_SHORT.update(SEPARATE_ONT_SHORT)
        ADVICE.update(SEPARATE_ONT_ADVICE)
        targets.append(Target("ont", ont, RANK_ONT))
        su.note(f"setup: router {gw} → ONT {ont} → fiber")
    else:
        su.note(f"setup: home router {gw} is also the modem (fiber box / modem-router); "
                "use --ont IP if you have a separate ONT/modem")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(args.out, stamp)
    os.makedirs(out_dir, exist_ok=True)

    # one traceroute finds the routers on the way (the ISP's first hops) to probe
    su.step(f"Tracing the route to {args.hosts[0]}, to find the ISP's routers")
    raw, hops = trace_hops(args.hosts[0], 20)
    with open(os.path.join(out_dir, "traceroute.txt"), "w") as f:
        f.write(f"== {args.hosts[0]}\n{raw}\n")
    # in direct mode the gateway is hop 1 and is the ISP's first router, so probe it too
    skip = (ont, *args.hosts) if direct else (gw, ont, *args.hosts)
    first_isp = 1 if direct else 2
    hops = [(n, ip) for n, ip in hops if n <= args.hops and ip not in skip]
    pingable = answers_echo([ip for _, ip in hops])
    found = []
    for n, ip in hops:
        if ip in pingable:
            isp = n == first_isp and (direct or not ont)
            targets.append(Target(f"hop{n}" + ("-isp" if isp else ""), ip, RANK_HOP + n, hop=n))
            found.append(f"hop{n} {ip}")
    if direct and gw and gw not in [ip for _, ip in hops] and gw in answers_echo([gw]):
        targets.append(Target("isp-gw", gw, RANK_HOP, hop=1))
        found.insert(0, f"isp-gw {gw}")
    su.done(f"{len(found)} routers to probe: {', '.join(found)}" if found else "no router on the way answers pings")
    skipped = [f"hop{n} {ip}" for n, ip in hops if ip not in pingable]
    if skipped:
        su.note(f"skipped, they don't answer pings: {', '.join(skipped)}")
    for h in args.hosts:
        targets.append(Target(h, h, RANK_DEST))
    su.step("Destinations")
    su.done(", ".join(f"{KNOWN_HOSTS.get(h, 'internet')} {h}" for h in args.hosts))
    if args.tcp:
        su.step("Finding a TCP port on each (handshake timing, like real traffic)")
        tcp = ([("ont", ont, RANK_ROUTER, None)] if ont else []) + \
              [(t.name, t.addr, RANK_DEST, t.hop) for t in targets if t.rank == RANK_DEST]
        ok, none = [], []
        for name, addr, rank, hop in tcp:
            port = open_tcp_port(addr)
            if port:
                targets.append(Target(f"{name}:{port}", addr, rank, hop=hop, port=port))
                ok.append(f"{addr}:{port}")
            else:
                none.append(addr)
        su.done(", ".join(ok) or "none answers on port 80/443", "✓" if ok else "⚠")
        if none:
            su.note(f"no open port 80/443, skipped: {', '.join(none)}")
    if args.extra:
        su.step("Extra probes for the Tests tab (big packets, priority markings, IPv6)")
        extra = extra_probes(targets, first_isp)
        targets += extra
        v6 = any(t.v6 for t in extra)
        su.done(f"{len(extra)} probes" + ("" if v6 else ", no IPv6 on this connection"))
    targets.sort(key=lambda t: t.rank)
    su.step("Checking that macOS lets this program reach the local network")
    blocked = check_local_network_access(targets)
    su.done(*((blocked, "⚠") if blocked else ("ok",)))
    su.step("Checking the Mac's clock (the timer moments are measured on it)")
    c = clock_offset()
    clock_start = (time.time(), *c) if c else None
    su.done(f"{c[0] * 1000:+.0f} ms off time.apple.com" if c else "time.apple.com not reachable",
            "✓" if c else "⚠")
    su.step("Starting the probes")

    full, link_samples, sampler = None, [], None
    counters_before = iface_counters(iface)
    err_samples = []    # (time, input errors) to correlate with loss events

    def sample_errors():
        # this Mac's own traffic and the interface errors, every second
        while not prober.stop.is_set():
            c = iface_counters(iface)
            if c:
                now = time.time()
                err_samples.append((now, c["ierrs"]))
                prober.traffic.append((now, c["ibytes"], c["obytes"], c["ierrs"]))
            prober.stop.wait(1)

    def run_status():
        # a command of the user's (e.g. reading the ONT's optical values), logged regularly
        while True:
            now = time.strftime("%H:%M:%S")
            try:
                out = subprocess.run(args.status_cmd, shell=True, capture_output=True, text=True,
                                     timeout=60)
                text = out.stdout + out.stderr
            except subprocess.TimeoutExpired:
                text = "(timed out after 60 s)\n"
            with open(os.path.join(out_dir, "status.txt"), "a") as f:
                f.write(f"== {now}\n{text}\n")
            prober.status_runs += 1
            if prober.stop.wait(args.status_every):
                break
    if link == "wifi":
        sampler = start_link_sampler(2.0, out_dir, link_samples)

    # hand the interpreter lock over every 1 ms (default 5 ms), so the analysis threads
    # don't delay the probe threads' timestamps
    sys.setswitchinterval(0.001)
    prober = Prober(targets, args.interval)
    tracker = EventTracker(prober, link_label)
    tracker.out_dir = out_dir
    started = time.time()
    prober.run()
    threading.Thread(target=sample_errors, daemon=True).start()

    def check_clock():
        c = clock_offset()
        if c:
            prober.clock_checks.append((time.time(), *c))
    if clock_start:
        prober.clock_checks.append(clock_start)
    if args.status_cmd:
        threading.Thread(target=run_status, daemon=True).start()
    tty = sys.stdout.isatty()
    term = None
    su.done()
    if tty:
        if sys.stdin.isatty():
            # keys without Enter and without echo, for scrolling the events list
            term = termios.tcgetattr(sys.stdin)
            ttymode.setcbreak(sys.stdin)
            threading.Thread(target=read_keys, args=(tracker, prober.stop), daemon=True).start()
    last_plain = last_save = 0
    try:
        while True:
            time.sleep(0.1 if tty else 0.5)
            tracker.update()
            if tty:
                render(prober, tracker, f"{link_label} {iface}", link_samples, started, True)
            elif time.time() - last_plain >= 5:
                last_plain = time.time()
                d = tracker.done
                print(f"{time.time() - started:6.0f}s  " + "  ".join(
                    f"{t.name}={sum(1 for v in t.rtt[:d] if v is None)}/{d}" for t in targets),
                    flush=True)
            if time.time() - last_save >= 10:
                last_save = time.time()
                save_probes(prober, tracker.done, out_dir)
                save_logs(prober, out_dir)
            if args.duration and time.time() - started >= args.duration:
                break
            if prober.slept:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if term:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, term)
        su.leave()
    if tty:     # the startup steps, for the scrollback (the screen showing them is gone)
        print("netdiag\n" + "\n".join(su.text()) + "\n")
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
    check_clock()       # again at the end: did the Mac's clock stay right?
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
                f"{t.rtt[n]:.3f}" if isinstance(t.rtt[n], float) else
                f"{RESENT}:{t.resend_ms.get(n, 0):.0f}" if t.rtt[n] is RESENT else ""
                for t in prober.targets)
                    + "\n")
    prober.saved = max(start, upto)


MARK_TOS = {m: tos for m, tos, _ in MARKINGS}


def target_from(name, row=None):
    """A Target for a saved run, from its summary.json row, or guessed from its name (a run
    that ended before writing one)."""
    probe = (row or {}).get("probe", "")
    m = re.fullmatch(r"(.+):(\d+)", name) if not name.startswith("v6-") else None
    port = int(m.group(2)) if m else (int(probe[4:].split(",")[0]) if probe.startswith("tcp:") else None)
    base = m.group(1) if m else name.split("·")[0]
    size = re.search(r"(\d+) ?B(?:ytes)?$", name.split("·")[-1]) if "·" in name else None
    mark = name.split("·")[-1] if "·" in name else None
    hop = re.match(r"hop(\d+)", base)
    rank = (row or {}).get("rank", RANK_ROUTER if base in ("home-router", "ont") else
                           RANK_HOP + int(hop.group(1)) if hop else
                           RANK_HOP + 2 if base == "v6-isp" else RANK_HOP if base == "isp-gw" else RANK_DEST)
    v6 = name.startswith("v6-")
    addr = (row or {}).get("addr") or (base if re.fullmatch(r"[\d.]+", base) else
                                     {f"v6-{v.lower()}": k for k, v in V6_HOSTS.items()}.get(name, base))
    return Target(name, addr, rank, (row or {}).get("hop"), port=port,
                  size=int(size.group(1)) if size else None, tos=MARK_TOS.get(mark, 0), v6=v6,
                  extra=(row or {}).get("extra", "·" in name or v6),
                  label=f"IPv6 {V6_HOSTS[addr]}" if v6 and addr in V6_HOSTS else None)


class Replay:
    """A finished run read back from its folder, standing in for the Prober, so `report`
    can analyze it again with the current version."""
    replay = True
    timeout, tcp_timeout, keep, status_runs = 1.0, 1.9, None, 0

    def __init__(self, folder):
        path = os.path.join(folder, "summary.json")
        self.summary = json.load(open(path)) if os.path.exists(path) else {}
        rows = {r["name"]: r for r in self.summary.get("targets", [])}
        # runs from before TCP resends were told apart from losses don't know them
        self.resent_known = any(r.get("resent") is not None for r in rows.values())
        with open(os.path.join(folder, "probes.csv")) as f:
            r = csv.reader(f)
            names = next(r)[2:]
            self.targets = [target_from(n, rows.get(n)) for n in names]
            self.send_t = []
            for row in r:
                n = len(self.send_t)
                self.send_t.append(float(row[1]))
                for t, v in zip(self.targets, row[2:]):
                    if not v:
                        t.rtt.append(None)
                    elif v.startswith(RESENT):
                        t.rtt.append(RESENT)
                        self.resent_known = True
                        if ":" in v and v.split(":")[1] != "0":
                            t.resend_ms[n] = float(v.split(":")[1])
                    else:
                        t.rtt.append(float(v))
        if len(self.send_t) < 2:
            sys.exit(f"{folder}: not enough probe rounds to analyze")
        self.interval = self.summary.get("interval") or round(
            (self.send_t[-1] - self.send_t[0]) / (len(self.send_t) - 1), 3)
        self.slept = self.summary.get("slept")
        self.misread = [0] * self.summary.get("misread", 0)
        self.argv = self.summary.get("argv")
        self.clock_checks = self.summary.get("clock") or []
        self.traffic, self.quality = [], []
        with contextlib.suppress(OSError, ValueError):
            with open(os.path.join(folder, "traffic.csv")) as f:
                next(f)
                self.traffic = [tuple(float(x) for x in line.split(",")) for line in f if line.strip()]
        with contextlib.suppress(OSError, ValueError):
            with open(os.path.join(folder, "quality.csv")) as f:
                next(f)
                # minutes are saved as local HH:MM: back to times, counting days from the start
                lt = time.localtime(self.send_t[0])
                day = self.send_t[0] - lt.tm_hour * 3600 - lt.tm_min * 60 - lt.tm_sec
                prev = 0
                for line in f:
                    if not line.strip():
                        continue
                    hm, a, b, c = line.strip().split(",")
                    m = day + int(hm[:2]) * 3600 + int(hm[3:5]) * 60
                    while m < max(prev, self.send_t[0] - 60):
                        m += 86400
                    self.quality.append([m, float(a), float(b), int(c)])
                    prev = m
        per_round = sum(60 if t.port else (t.size or (48 if t.v6 else 20) + 8 + 25)
                        for t in self.targets)
        self.probe_kbps = per_round * 8 / 1000 / self.interval

    def done_rounds(self):
        return len(self.send_t)


def cmd_report(args):
    """Analyze a saved run again, with this version of the analysis."""
    rp = Replay(args.dir)
    old, kept = os.path.join(args.dir, "report.txt"), os.path.join(args.dir, "report.before.txt")
    if os.path.exists(old) and not os.path.exists(kept):
        shutil.copy(old, kept)      # the first report stays around for comparison
    setup = rp.summary.get("setup", "router")
    for text, short, advice in ((DIRECT_ONT_TEXT, DIRECT_ONT_SHORT, DIRECT_ONT_ADVICE),
                                (SEPARATE_ONT_TEXT, SEPARATE_ONT_SHORT, SEPARATE_ONT_ADVICE)):
        if setup == ("direct" if text is DIRECT_ONT_TEXT else "router+ont"):
            SEGMENT_TEXT.update(text)
            SEGMENT_SHORT.update(short)
            ADVICE.update(advice)
    link = rp.summary.get("link") or ("wifi" if os.path.exists(os.path.join(args.dir, "wifi.json"))
                                       else "ethernet")
    tracker = EventTracker(rp, "Wi-Fi" if link == "wifi" else "Ethernet/LAN")
    tracker.out_dir = args.dir
    print(f"Analyzing {args.dir} again ({len(rp.send_t)} probe rounds)...")
    tracker.update()
    full, samples = None, []
    with contextlib.suppress(OSError, ValueError):
        w = json.load(open(os.path.join(args.dir, "wifi.json")))
        full, samples = w.get("scan"), w.get("samples", [])
    errs = [(t, e) for t, _, _, e in rp.traffic]
    report(rp, tracker, link, rp.summary.get("iface", "?"), full, samples, None, args.dir, errs, setup)


def save_logs(prober, out_dir):
    """The side logs: own traffic per second (appended), measurement quality per minute,
    route changes (TTL of the replies, traceroutes) and reply markings (rewritten)."""
    start = getattr(prober, "saved_traffic", 0)
    rows = prober.traffic[start:]
    with open(os.path.join(out_dir, "traffic.csv"), "a" if start else "w") as f:
        if not start:
            f.write("time,bytes_in,bytes_out,input_errors\n")
        f.writelines(f"{t:.1f},{i},{o},{e}\n" for t, i, o, e in rows)
    prober.saved_traffic = start + len(rows)
    with open(os.path.join(out_dir, "quality.csv"), "w") as f:
        f.write("minute,worst_send_delay_ms,worst_read_delay_ms,replies_read_too_late\n")
        f.writelines(f"{time.strftime('%H:%M', time.localtime(m))},{a:.1f},{b:.1f},{c}\n"
                     for m, a, b, c in list(prober.quality))
    with open(os.path.join(out_dir, "paths.txt"), "w") as f:
        f.write("Reply TTL / hop limit changes (a changed route) and reply markings (TOS) per target\n")
        for t in prober.targets:
            if t.port:
                continue
            tos = ", ".join(f"0x{k:02x}: {v}" for k, v in t.reply_tos.most_common())
            f.write(f"\n{t.name} ({t.addr}): TTL {t.ttl}, reply TOS {tos or '-'}\n")
            for when, ttl in t.ttl_changes:
                f.write(f"  {clock(when)}  TTL → {ttl}\n")


def _report(prober, tracker, link, iface, full, link_samples, counters_before, out_dir, err_samples,
            info):
    done = tracker.done
    # the extra probes get their statistics, but stay out of the loss analysis
    targets = [t for t in prober.targets if not t.extra]
    if not done:
        print("Stopped before any probe round completed.")
        return None

    replay = getattr(prober, "replay", False)
    if not replay:         # a replay keeps the raw data as it is
        save_probes(prober, done, out_dir)
        save_logs(prober, out_dir)
    with open(os.path.join(out_dir, "events.json"), "w") as f:
        json.dump([{**e, "targets": sorted(e["targets"])} for e in tracker.events], f, indent=1)
    if link_samples or full:
        with open(os.path.join(out_dir, "wifi.json"), "w") as f:
            json.dump({"scan": full, "samples": link_samples}, f, indent=1)

    dur = prober.send_t[done - 1] - prober.send_t[0]
    print(f"\nRan {dur / 60:.1f} min, {done} probe rounds every {prober.interval * 1000:.0f} ms. "
          f"Raw data: {out_dir}/")
    print(f"Command: {' '.join(['netdiag.py'] + (getattr(prober, 'argv', None) or sys.argv[1:]))}"
          + ("  (analyzed again with this version)" if replay else ""))
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
    for t in prober.targets:
        series = analyze_series({n: t.rtt[n] for n in range(done)}, prober.interval)
        series["tcp"] = bool(t.port)
        stats[t.name] = series
        print_series(f"{t.name} ({t.addr}, {probe_label(t)})", series)
        if t.late:
            print(f"  late      {t.late} replies arrived after the {prober.timeout:.0f}s timeout")
        if t.extra:
            continue
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

    # loss over time: only the timers that are statistically significant over the whole run
    first, last = prober.send_t[0], prober.send_t[done - 1]
    timers = scan_views(tracker.loss_t, first, last, prober.interval, None, guesses=0)[0][5]
    info["timers"] = [{"period": c["period"], "phase": round(c["phase"], 3), "hits": c["hits"],
                       "cycles": c["cycles"]} for c in timers if significance(c) == 2]
    tracker.timers = [c for c in timers if significance(c) == 2]
    with open(os.path.join(out_dir, "events.txt"), "w") as f:     # losses at a timer tagged
        f.write("time        type    lasted  targets\n")
        f.writelines(event_line(e, prober.interval, False, tracker.timers) + "\n"
                     for e in tracker.events)
    print("\n── Loss over time " + "─" * 44)
    for line in loss_over_time(tracker.isp_loss, first, last, prober.interval, timers, 80, False,
                               False):
        print(line)
    comp = comparisons(prober, tracker)
    info["comparisons"] = comp
    if comp:
        print("\n── Comparisons " + "─" * 47)
        for topic, text in comp:
            print(f"  {topic:<18}" + wrap(text, 58, " " * 20))
    trend = trend_lines(prober, tracker, 120, False, link_samples)
    if trend:
        print("\n── Trends: what changed over the run " + "─" * 25)
        for line in trend:
            print(line)

    findings = localize(tracker, targets, stats, prober.interval, info) + findings
    per = tracker.period(force=True)
    info["periodic"] = per
    if per:
        P, w = per["period"], per["window"] / 2
        in_win = [n for n in range(done)
                  if abs((prober.send_t[n] - per["phase"] + P / 2) % P - P / 2) <= w]
        alive = sorted((t for t in targets if t.name not in tracker.dead),
                       key=lambda t: (t.rank, t.port or 0))
        hit = [t for t in alive if any(is_lost(t.rtt[n]) for n in in_win)]
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
    elif not replay:       # today's interface counters say nothing about an old run
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
                     "resent": r.get("resent", 0) if getattr(prober, "resent_known", True) else None,
                     "p50": round(r["p50"], 2) if "p50" in r else None,
                     "silent": t.name in tracker.dead, "extra": t.extra})
    summary = {"start": prober.send_t[0], "end": prober.send_t[done - 1], "rounds": done,
               "interval": prober.interval, "link": link, "setup": setup, "targets": rows,
               "verdict": info.get("verdict"), "shared": info.get("shared"),
               "periodic": info.get("periodic"), "comparisons": info.get("comparisons"),
               "slept": prober.slept, "misread": len(prober.misread),
               "timers": info.get("timers"), "clock": prober.clock_checks,
               "argv": getattr(prober, "argv", None) or sys.argv[1:]}
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)


def cmd_summarize(args):
    """Compare several runs (e.g. different times of day) side by side."""
    paths = sorted(p for d in args.dirs for p in glob.glob(os.path.join(d, "**", "summary.json"),
                                                           recursive=True))
    if not paths:
        sys.exit("No summary.json found (runs made with this version of netdiag write one).")
    head = ("| start | min | setup | probe | first device | ISP first hop | internet ICMP "
            "| internet TCP: resent / lost | loss starts | timers | tests |")
    lines = [head, "|" + "---|" * 11]
    for p in paths:
        s = json.load(open(p))
        live = [t for t in s["targets"] if not t["silent"] and not t.get("extra")]
        icmp = [t for t in live if t["probe"] == "icmp"]
        first = next((t for t in icmp if t["rank"] == RANK_ROUTER), None)
        hops = [t for t in icmp if RANK_HOP <= t["rank"] < RANK_DEST]
        isp = min(hops, key=lambda t: t["rank"]) if hops else None
        med = lambda ts: f"{statistics.median(t['loss_pct'] for t in ts):.2f}%" if ts else "-"
        dest_icmp = [t for t in icmp if t["rank"] == RANK_DEST]
        dest_tcp = [t for t in live if t["probe"].startswith("tcp") and t["rank"] == RANK_DEST]
        # TCP: loss_pct counts resends too; "resent" (newer runs) says how many of them
        tcp = "-"
        if dest_tcp:
            res = statistics.median(100 * (t.get("resent") or 0) / max(1, t["sent"]) for t in dest_tcp)
            tcp = f"{res:.2f}% / {statistics.median(t['loss_pct'] for t in dest_tcp) - res:.2f}%" \
                if all(t.get("resent") is not None for t in dest_tcp) else med(dest_tcp) + " (not split)"
        timers = ", ".join(f"{c['period']} s ({100 * c['hits'] / c['cycles']:.0f}%)"
                           for c in s.get("timers") or []) or (
            f"{s['periodic']['period']} s" if s.get("periodic") else "-")
        # tests in short: = no clear difference, ≠ a clear one; direction as down / up
        short = {"Packet size": "size", "Priority marking": "marking", "IPv4 vs IPv6": "IPv6"}
        tests = []
        for topic, text in s.get("comparisons") or []:
            if topic in short:
                tests.append(f"{short[topic]} {'=' if 'no clear difference' in text else '≠'}")
            elif topic == "Direction" and "→ you" in text:
                m = re.search(r"ISP → you ([\d.]+%), you → ISP ([\d.]+%)", text)
                if m:
                    tests.append(f"down {m.group(1)} / up {m.group(2)}")
        tests = ", ".join(dict.fromkeys(tests)) or "-"
        v = s.get("verdict")
        fmt = lambda t: f"{t['name']} {t['loss_pct']:.2f}%" if t else "-"
        lines.append(
            f"| {time.strftime('%a %Y-%m-%d %H:%M', time.localtime(s['start']))} "
            f"| {(s['end'] - s['start']) / 60:.0f} | {s['setup']}/{s['link']} "
            f"| {s['interval'] * 1000:.0f} ms | {fmt(first)} | {fmt(isp)} | {med(dest_icmp)} "
            f"| {tcp} | {(v['from'] + ' → ' + v['to']) if v else 'unclear'} "
            f"| {timers} | {tests} |")
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
    found.sort(key=lambda c: c["p"])
    # A timer every 30 s makes every 6 s (10 s, 15 s) look regular too: one of the 6 s moments
    # always hits, and the shorter interval has more cycles, so it can win on odds. Then
    # most of the 6 s hits sit in one of the five 6 s slots of a 30 s cycle, while a real
    # 6 s timer spreads them evenly (1/k each): take the multiple if its slot holds clearly
    # more than that, halfway to all of them.
    changed = True
    while found and changed:
        changed, best = False, found[0]
        P = best["period"]
        for m in sorted(found, key=lambda c: c["period"]):
            k = m["period"] // P
            if (m["period"] > P and m["period"] % P == 0 and significance(m)
                    and m["hits"] >= (1 + 1 / k) / 2 * best["hits"]
                    and abs((m["phase"] - best["phase"] + P / 2) % P - P / 2)
                    <= best["window"] + m["window"]):
                found.remove(m)
                found.insert(0, m)
                changed = True
                break
    return found


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
    # four destinations behind different exits of a typical ISP (an internet exchange,
    # direct links to big networks, transit carriers), so a problem on one path shows up
    r.add_argument("--hosts", nargs="+",
                   default=["1.1.1.1", "8.8.8.8", "208.67.222.222", "185.15.58.224"])
    r.add_argument("--no-tcp", dest="tcp", action="store_false",
                   help="don't add TCP handshake probes (port 80/443) to the ONT and internet hosts")
    r.add_argument("--no-extra", dest="extra", action="store_false",
                   help="don't add the extra probes (big packets, priority markings, IPv6)")
    r.add_argument("--status-cmd", help="shell command whose output is logged to status.txt "
                   "regularly, e.g. one that reads the ONT's optical values")
    r.add_argument("--status-every", type=int, default=300, help="seconds between --status-cmd runs")
    r.add_argument("--out", default="netdiag-logs")
    r.set_defaults(func=cmd_run)
    rp = sub.add_parser("report", help="analyze a saved run again with this version")
    rp.add_argument("dir", help="the run's folder, e.g. netdiag-logs/20261109-231641")
    rp.set_defaults(func=cmd_report)
    sm = sub.add_parser("summarize", help="compare saved runs side by side")
    sm.add_argument("dirs", nargs="*", default=["netdiag-logs"])
    sm.add_argument("--out", default="netdiag-logs/summary.md", help="also save the table here")
    sm.set_defaults(func=cmd_summarize)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
