# Ethernet Frame Capture (Scapy)

A tiny Wireshark‑style **CLI packet sniffer** written in Python with [Scapy]. It prints **Ethernet / IPv4 / IPv6 / TCP / UDP / ARP / ICMP** headers in readable, colored text and can **optionally save** packets to a `.pcap` for later analysis.

> Works on **Linux / macOS / Windows**. Live sniffing typically requires **root/Administrator** privileges.



## Features

* Live sniffing with **optional BPF filter** (e.g., `port 53`, `tcp or arp`).
* **Interface selection** (or auto‑select the default interface if omitted).
* **Packet limit** (`-c`) and **time limit** (`--timeout`).
* **Append‑safe PCAP writing** with `-w FILE.pcap`.
* Clean **colored output** (disable with `--no-color`).
* End‑of‑run **summary with per‑protocol counts and percentages**.



## Project structure

```text
ethernet-frame-cap/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── ethernet_cap.py     # main program
├── run.py              # convenience launcher 
├── bootstrap.py        # create venv + install dependencies
└── captures/           # kept in git via .gitkeep, .pcap files ignored
    └── .gitkeep
```



## Quick start

### Prerequisites

* **Python 3.8+**
* **Scapy** and **Colorama** (installed via `requirements.txt`)
* Live sniff: run as **root/Administrator**

### 1) Clone & set up

```bash
git clone <your-repo-url>
cd ethernet-frame-cap
python bootstrap.py
```

This creates a `.venv/` and installs requirements.

### 2) Run

```bash
# Default interface, no filter (Ctrl+C to stop)
python run.py

# Stop after 20 packets
python run.py -c 20

# Stop after 10 seconds
python run.py --timeout 10

# DNS only (UDP/TCP 53), save to PCAP
python run.py -f "port 53" -c 50 -w captures/dns_$(date +%s).pcap
```

> **Note:** You’ll be prompted for your password the first time. Subsequent runs in the same terminal may *not* prompt because credentials are caches for a short period.\




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



## Saving & inspecting PCAPs

* Use `-w FILE.pcap` to **append** packets to a PCAP:

  ```bash
  python run.py -f "port 53" -c 50 -w captures/dns_test.pcap
  ```
* Quick peek with `tcpdump`:

  ```bash
  tcpdump -r captures/dns_test.pcap | head
  ```
* Or open in Wireshark.

> The repo ignores `captures/*` by default but keeps the folder via `.gitkeep`.



## Troubleshooting

**Permission denied / no packets**

* Live sniffing needs root/Administrator.
* On Linux/macOS, `run.py` auto-relaunches itself with `sudo`.


**Interface not found**

* Use the correct platform name (`en0` on macOS, often `wlan0`/`eth0` on Linux).
* List interfaces with `get_if_list()` or (macOS) `networksetup -listallhardwareports`.


**BPF filter error**

* Validate your filter; try a simple one first (e.g., `arp`), then expand.

**Zero packets captured**

* Wrong interface or too strict filter; try without `-f`.
* Some Wi‑Fi drivers/interfaces don’t support certain modes without extra setup.



## Development notes

* The script uses Scapy’s `sniff()` with `prn` callback and optional `count`/`timeout`.
* PCAP writing is done via `PcapWriter(..., append=True, sync=True)` to avoid overwrites and reduce data loss on interrupt.
* End‑of‑run summary is collected with `collections.Counter` and printed as counts and percentages.




## Security & ethics

Use this tool **only on networks you own or have explicit permission to monitor**. Respect laws, privacy, and institutional policies.



## License

This project is licensed under the **MIT License**. See `LICENSE` for details.



## Credits

* [Scapy] – powerful packet crafting & sniffing
* [Colorama] – portable ANSI colors on Windows/macOS/Linux

[Scapy]: https://scapy.net/
[Colorama]: https://pypi.org/project/colorama/
