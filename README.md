# internet-connection-loss-debugger

https://github.com/user-attachments/assets/4d031659-7afe-48c0-be07-ffb226895545

Find out **where** packet loss and latency spikes on your internet connection come from:
your Wi-Fi, your router, the line to your ISP, or the ISP's network. Built for macOS;
needs only the Python 3 that ships with it.

Instead of pinging one host, `netdiag.py` probes every station on the path **at the same
moment** — your home router, the first hops of your ISP, and four destinations that a
typical ISP reaches over different exits (Cloudflare 1.1.1.1, Google 8.8.8.8, OpenDNS
208.67.222.222, Wikipedia 185.15.58.224; ICMP and TCP handshakes) — 20 times per second. Where the loss rate steps up and stays up for everything
behind it is where packets get lost.

## Quick start

```sh
git clone https://github.com/vonox7/internet-connection-loss-debugger.git
cd internet-connection-loss-debugger
./netdiag.py run          # live dashboard; Ctrl+C stops it and prints the report
```

Let it run for 30 minutes or more, ideally at a time when the connection feels bad.
Everything (gateway, hops, Wi-Fi vs. Ethernet) is detected automatically, nothing is
hardcoded, so you can hand the script to anyone.

On macOS 15+, your terminal app needs the **Local Network** permission (System Settings →
Privacy & Security → Local Network) to reach the router; the tool warns you if it's missing.

## What you see while it runs

The tool runs full screen (like `top`; your terminal comes back as it was when it ends). A
startup screen ticks off each preparation step (connection, route, TCP ports, extra probes,
clock), then six views take over, switched with ← / → or `1`–`6` (tabs at the top):

**1 Live** — what's happening right now?
- **Probes**: per station its loss (for TCP also "resent": a packet got lost, but TCP's
  resend got through, as it does for real traffic), latency and a timeline with one column
  per second: the bar shows how much slower than usual it answered (yellow █ = latency
  spike), the digit below how many probes got lost in that second. A row flashes the moment
  a probe is lost.
- **Events**: every loss / spike with time, duration and which stations were hit; losses at
  the moment of a regular timer say so ("30 s timer"). Scroll with ↑/↓, PgUp/PgDn, Home/End.

**2 Timeline** — when does it happen?
- **Loss over time**: per protocol a chart with one column per 10 minutes (coarser on long
  runs, up to 24 h) and the loss per hour: ICMP split into the regular timers found below
  and the random rest, TCP into resent and lost. Loss that rises and falls with the time of
  day (high in the evening, low at 3 am) points to an overloaded network rather than a
  damaged line.
- **Regular loss intervals**: checks whether losses repeat on a fixed timer (every 1–300 s,
  at the same moment of the cycle), with the moment, how tightly the losses cluster, how
  fast the moment drifts, and how likely that pattern is pure luck. A device that runs a
  periodic job and briefly stops forwarding shows up here. Press `h` for an explanation.

**3 Tests** — what kind of loss is it? Each with an explanation, a statistical verdict and
its probes next to the normal ones they're compared with:
- *direction*: a server that resends a lost reply sooner than macOS resends a lost request
  (Google: ~0.3 s vs ~1 s) shows whether packets get lost on the way to you or from you;
- *packet size*: 1400-byte vs small pings. Bit errors on a line hit big packets more often,
  an overloaded queue drops both alike;
- *priority marking*: pings marked EF / AF41 / CS1 vs unmarked, to the ISP's first hop;
- *IPv4 vs IPv6*: a different path through the ISP (no carrier-grade NAT);
- *your own traffic*: was the line quiet when packets got lost?

**4 Trends / 5 Test trends** — what changed over the run, and what didn't? (Made for the
morning after a night run.) One chart per topic, in the style of the loss-over-time chart,
with its series as grouped bars (e.g. small and big packets side by side per time slot),
and per series the first and the last hour, the lowest and the highest hour, and whether
start and end differ (with a statistical test for the loss rates). *Trends*: loss per
destination, TCP resent / lost, latency, direction. *Test trends*: packet size, priority
marking, IPv4 vs IPv6, your own traffic, Wi-Fi signal, route changes, measurement quality.
The report has the same section.

**6 Raw** — can the measurement be trusted? TTL (a change = a new route) and marking of the
replies per station, this Mac's traffic and interface errors, the tool's own delays, and how
far the Mac's clock is off (checked against time.apple.com at the start and the end; the
timer moments are measured on it).

## The report

After Ctrl+C (or `-d SECONDS`) you get per-station statistics and findings, e.g.

```
⚠ VERDICT: loss is 0.00% up to home-router and 0.50% from hop2-isp on, and stays that
  high for everything behind it, so packets are lost between home-router and hop2-isp:
  your internet line between the home router and the ISP's first router …
⚠ The losses recur on a fixed timer: every 30 s at :23.72 / :53.72, losses within
  59 ms: 21 of 22 cycles (expected by chance: ~2) …
```

| loss starts at …              | means                                             |
|-------------------------------|---------------------------------------------------|
| the home router               | your Wi-Fi / LAN                                  |
| the ISP's first hop           | your internet line (modem/ONT, fiber/cable, ISP access network) |
| a later ISP hop               | inside the ISP's network                          |
| only one intermediate hop     | that hop just rate-limits pings (harmless)        |

Everything is saved in `netdiag-logs/<timestamp>/` (during the run too): `report.txt`,
`events.txt` / `events.json` (all events), `probes.csv` (every single probe),
`traceroute.txt`, `traffic.csv` (this Mac's traffic and interface errors per
second), `quality.csv` (the tool's own delays per minute), `paths.txt` (TTL changes and
reply markings), `summary.json`. These files contain your IP addresses, so check them before sharing.

Compare several runs (different times of day) with:

```sh
./netdiag.py summarize      # also writes netdiag-logs/summary.md
```

One row per run: loss at your first device, at the ISP's first hop and on the internet
(ICMP; TCP split into resent and lost), where the loss starts, the regular timers found and
the test results.

Analyze a saved run again with the current version (e.g. after an update of the tool):

```sh
./netdiag.py report netdiag-logs/20261109-231641   # keeps the old one as report.before.txt
```

## Options

```
./netdiag.py run -i 0.2            # probe every 200 ms instead of 50 ms
./netdiag.py run -d 1800           # stop after 30 minutes
./netdiag.py run --link ethernet   # skip Wi-Fi / Ethernet detection
./netdiag.py run --ont 192.168.100.1   # a separate ONT/modem with its own IP before the router
./netdiag.py run --hops 8 --hosts 1.1.1.1 9.9.9.9
./netdiag.py run --no-tcp          # ICMP only
./netdiag.py run --no-extra        # without the big / marked / IPv6 extra probes
./netdiag.py run --status-cmd 'CMD' # log CMD's output every 5 min (status.txt), e.g. a
                                   # script that reads your ONT's optical values
./netdiag.py analyze ping-log.txt  # analyze a saved `ping` output
```

## Testing without your router: `ont-connect.sh`

If the loss starts right after your router, the next question is: the router, or the line?
`ont-connect.sh` connects the Mac directly to the fiber ONT (or modem) and does the
router's job itself:

```sh
./ont-connect.sh                  # asks for the ISP's internet VLAN (Enter = 31)
./ont-connect.sh --vlan 7         # ISP delivers internet on VLAN 7
./ont-connect.sh --no-vlan        # ISP delivers internet untagged
./ont-connect.sh --browser        # also open the ONT's web page (optical levels, errors)
```

Unplug the router from the ONT, plug in the Mac, run the script. It reaches the ONT's
management address (default `192.168.100.1`, change with `--ont`), gets an address from
the ISP via DHCP (the VLAN ID is in your router's internet/WAN settings), and starts the
analyzer in a new terminal window. Press Enter in the script's window when you're done:
it restores your network settings. PPPoE connections aren't supported.

If the ONT itself answers without loss but everything behind it loses packets, your own
equipment is ruled out and the problem is on the line / ISP side.

## How it works

- Unprivileged ICMP sockets (no sudo) plus non-blocking TCP handshakes; all stations get
  one probe per round at the same moment, so losses on a shared segment line up.
- Localization like `mtr`, but with a check that two destinations losing in the same round
  happens far more often than chance (real shared loss, not ICMP rate limiting).
- Periodicity: for every interval and phase, counts cycles with a loss at that moment,
  compares with random loss (binomial tail) and corrects for having searched all
  intervals; validated against random-loss simulations.
- Wi-Fi: link state through CoreWLAN without triggering scans (a scan itself causes
  spikes); a neighbor scan only runs after the test, and only if the Wi-Fi hop lost packets.

## License

MIT
