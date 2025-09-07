# Ethernet Frame Capture (Scapy)

A tiny Wireshark‑style **CLI packet sniffer** written in Python with [Scapy]. It prints **Ethernet / IPv4 / IPv6 / TCP / UDP / ARP / ICMP** headers in readable, colored text and can **optionally save** packets to a `.pcap` for later analysis.

> Works on **Linux / macOS / Windows**. Live sniffing typically requires **root/Administrator** privileges.

---

## Features

* Live sniffing with **optional BPF filter** (e.g., `port 53`, `tcp or arp`).
* **Interface selection** (or auto‑select the default interface if omitted).
* **Packet limit** (`-c`) and **time limit** (`--timeout`).
* **Append‑safe PCAP writing** with `-w FILE.pcap`.
* Clean **colored output** (disable with `--no-color`).
* End‑of‑run **summary with per‑protocol counts and percentages**.

---

## Project structure

```text
ethernet-frame-cap/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── ethernet_cap.py     # main program
├── run.sh              # convenience launcher (Linux/macOS)
├── setup.sh            # create venv + install dependencies
└── captures/           # kept in git via .gitkeep, .pcap files ignored
    └── .gitkeep
```

---

## Quick start

### Prerequisites

* **Python 3.8+**
* **Scapy** and **Colorama** (installed via `requirements.txt`)
* Live sniff: run as **root/Administrator**

### 1) Clone & set up

```bash
git clone <your-repo-url>
cd ethernet-frame-cap
./setup.sh
```

This creates a `.venv/` and installs requirements.

> If you prefer manual setup:
>
> ```bash
> python3 -m venv .venv
> source .venv/bin/activate
> pip install -r requirements.txt
> ```

### 2) Run

```bash
# Default interface, no filter (Ctrl+C to stop)
sudo ./run.sh

# Stop after 20 packets
sudo ./run.sh -c 20

# Stop after 10 seconds
sudo ./run.sh --timeout 10

# DNS only (UDP/TCP 53), save to PCAP
sudo ./run.sh -f "port 53" -c 50 -w captures/dns_$(date +%s).pcap
```

> **Note:** `run.sh` auto‑elevates with `sudo` for live sniffing. You’ll be prompted for your password the first time. Subsequent runs in the same terminal may *not* prompt because `sudo` caches credentials for a short period. Use `sudo -k` (or `sudo -K`) to force a re‑prompt.

> On Windows, run your terminal **as Administrator** and execute:
>
> ````powershell
> .\.venv\Scripts\python.exe ethernet_cap.py -c 20
> ```powershell
> .\.venv\Scripts\python.exe ethernet_cap.py -c 20
> ````

---

## Usage

```text
usage: ethernet_cap.py [-h] [-i IFACE] [-f FILTER] [-c COUNT] [-w FILE.pcap]
                       [--timeout SECONDS] [--no-color]

Text-only Ethernet/IP sniffer (Scapy)

optional arguments:
  -i, --iface IFACE      Interface (e.g., eth0, wlan0, en0). If omitted, Scapy
                         uses its default interface.
  -f, --filter FILTER    BPF filter (e.g., 'tcp or arp', 'port 53').
  -c, --count COUNT      Stop after N packets (0 = infinite).
  -w, --write FILE.pcap  Append packets to this PCAP file.
  --timeout SECONDS      Stop after N seconds (0 = no timeout).
  --no-color             Disable colored output.
```

### Common BPF examples

```bash
# ARP only
-f "arp"

# DNS only
-f "port 53"

# ICMP (pings)
-f "icmp"

# Web traffic
-f "tcp and (port 80 or port 443)"

# Specific host or subnet
-f "host 8.8.8.8"
-f "net 192.168.1.0/24"
```

---

## Choosing an interface

If `-i/--iface` is omitted, Scapy uses its default interface (`conf.iface`).

**List interfaces** quickly with Scapy:

```bash
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

**Platform notes**

* **Linux:** Wi‑Fi is often `wlan0`, Ethernet `eth0` (but names may differ; use `ip link show`).
* **macOS:** Interfaces are named `en0`, `en1`, etc. Find your Wi‑Fi device:

  ```bash
  networksetup -listallhardwareports
  ```

  Example: `Hardware Port: Wi-Fi` → `Device: en0`
* **Windows:** Use the name shown by `get_if_list()` or `ipconfig` output.

**Examples**

```bash
# macOS Wi‑Fi for 10 seconds
sudo ./run.sh -i en0 --timeout 10

# Linux Wi‑Fi (if yours is wlan0)
sudo ./run.sh -i wlan0 -c 100
```

---

## Output example

```
15:24:27 ETH aa:bb:cc:dd:ee:ff → ff:ff:ff:ff:ff:ff type=ARP
       ARP request: aa:bb:cc:dd:ee:ff(192.168.1.5) → 00:00:00:00:00:00(192.168.1.1)
15:24:28 ETH 00:11:22:33:44:55 → 66:55:44:33:22:11 type=IPv4
       IPv4 192.168.1.5 → 8.8.8.8 ttl=64 len=74 proto=17
       UDP  56231 → 53 len=46
...
* Summary: total=187
  arp=2 (1.1%)
  ipv4=175 (93.6%)
  ipv6=10 (5.3%)
  tcp=120 (64.2%)
  udp=55 (29.4%)
```

---

## Saving & inspecting PCAPs

* Use `-w FILE.pcap` to **append** packets to a PCAP:

  ```bash
  sudo ./run.sh -f "port 53" -c 50 -w captures/dns_test.pcap
  ```
* Quick peek with `tcpdump`:

  ```bash
  tcpdump -r captures/dns_test.pcap | head
  ```
* Or open in Wireshark.

> The repo ignores `captures/*` by default but keeps the folder via `.gitkeep`.

---

## Troubleshooting

**Permission denied / no packets**

* Live sniffing needs root/Administrator.
* On macOS, prefer `python3` from your venv and run via `sudo ./run.sh`.

**Why didn’t it ask for my password this time?**

* `run.sh` re‑execs itself with `sudo` for live capture. `sudo` caches your authentication for a short time per terminal, so subsequent runs may not prompt again. Use `sudo -v` to refresh, `sudo -k`/`sudo -K` to expire the cache.

**Interface not found**

* Use the correct platform name (`en0` on macOS, often `wlan0`/`eth0` on Linux).
* List interfaces with `get_if_list()` or (macOS) `networksetup -listallhardwareports`.

**Run without sudo (optional)**

* **macOS:** Install Wireshark’s *ChmodBPF* package (adds a launch daemon and group‑writable `/dev/bpf*`), then ensure your user is in the appropriate group. Log out/in.
* **Linux:** Add your user to the `wireshark` group and set capabilities on `dumpcap`:

  ```bash
  sudo usermod -aG wireshark $USER
  sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
  ```

  (Depending on libpcap backend, Scapy may then capture without sudo.)

**BPF filter error**

* Validate your filter; try a simple one first (e.g., `arp`), then expand.

**Zero packets captured**

* Wrong interface or too strict filter; try without `-f`.
* Some Wi‑Fi drivers/interfaces don’t support certain modes without extra setup.

---

## Development notes

* The script uses Scapy’s `sniff()` with `prn` callback and optional `count`/`timeout`.
* PCAP writing is done via `PcapWriter(..., append=True, sync=True)` to avoid overwrites and reduce data loss on interrupt.
* End‑of‑run summary is collected with `collections.Counter` and printed as counts and percentages.

### Local testing tips

```bash
# Format: show only a few packets
sudo ./run.sh -c 10

# Verbose network activity generator (in another terminal)
ping -c 5 1.1.1.1
nslookup openai.com
curl http://example.com
```

---

## Security & ethics

Use this tool **only on networks you own or have explicit permission to monitor**. Respect laws, privacy, and institutional policies.

---

## License

This project is licensed under the **MIT License**. See `LICENSE` for details.

---

## Credits

* [Scapy] – powerful packet crafting & sniffing
* [Colorama] – portable ANSI colors on Windows/macOS/Linux

[Scapy]: https://scapy.net/
[Colorama]: https://pypi.org/project/colorama/
