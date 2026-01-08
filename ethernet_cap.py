#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Simple Wireshark-style text sniffer using Scapy
#   - Linux/macOS/Windows (run with admin/root)
#   - Interface selection, BPF filter, packet limit
#   - Optional PCAP saving (append-safe)
#   - Colored output (disable with --no-color)

import argparse
from datetime import datetime
from colorama import init as color_init, Fore, Style
from scapy.all import (
    sniff, PcapWriter,
    Ether, ARP, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply
)
from collections import Counter  # ADD


# ---------------------- CLI ----------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Text-only Ethernet/IP sniffer (Scapy)."
    )
    p.add_argument("-i", "--iface", help="Interface name (e.g., eth0, wlan0). If omitted, Scapy chooses.")
    p.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp or arp', 'port 53').")
    p.add_argument("-c", "--count", type=int, default=0, help="Stop after N packets (0 = infinite).")
    p.add_argument("-w", "--write", metavar="FILE.pcap", help="Write captured packets to PCAP (append).")
    p.add_argument("--no-color", action="store_true", help="Disable colored output.")
    p.add_argument("--timeout", type=int, default=0, help="Stop after N seconds (0 = no timeout).")

    return p.parse_args()

# ---------------------- Colors ----------------------
def setup_colors(disable=False):
    color_init(autoreset=True)
    if disable:
        class NoC:
            def __getattr__(self, _): return "" 
            # Python calls __getattr__(self, name) whenever you try to access an attribute that doesn’t exist. In this case, It'll always return an empty String ""
        return NoC(), NoC(), ""
    return (
        type("C", (), dict(
            ETH=Fore.CYAN, ARP=Fore.YELLOW, IP=Fore.GREEN,
            TCP=Fore.MAGENTA, UDP=Fore.BLUE, ICMP=Fore.LIGHTBLACK_EX,
            ERR=Fore.RED
        ))(),
        Style, Style.RESET_ALL
    )

# ---------------------- Formatting helpers ----------------------
def ts():
    return datetime.now().strftime("%H:%M:%S")

def eth_type_to_name(t):
    mapping = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "802.1Q"}
    return mapping.get(t, f"0x{t:04x}")

def tcp_flags_str(tcp):
    # F S R P A U E C (FIN SYN RST PSH ACK URG ECE CWR)
    flags = tcp.flags
    order = [("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08),
             ("A", 0x10), ("U", 0x20), ("E", 0x40), ("C", 0x80)] #Each touples = (symbol, bitmask)
    return "".join(sym for sym, bit in order if flags & bit) or "-"

# ---------------------- Packet printer ----------------------
def print_packet(pkt, C, S, R):
    # Ethernet
    if Ether in pkt:
        e = pkt[Ether]
        print(f"{ts()} {C.ETH}ETH{R} {e.src} → {e.dst} type={eth_type_to_name(e.type)}")
        # This '→ ' is just a uncode character, we can write it by '\u2192', RIGHTWARDS ARROW
    # ARP
    if ARP in pkt:
        a = pkt[ARP]
        op = "request" if a.op == 1 else "reply" if a.op == 2 else str(a.op)
        print(f"       {C.ARP}ARP{R} {op}: {a.hwsrc}({a.psrc}) → {a.hwdst}({a.pdst})")

    # IPv4
     # pylint: disable=too-many-branches
    if IP in pkt:
        ip = pkt[IP]
        print(f"       {C.IP}IPv4{R} {ip.src} → {ip.dst} ttl={ip.ttl} len={ip.len} proto={ip.proto}") #tll = time to live
        if TCP in pkt:
            t = pkt[TCP]
            print(f"       {C.TCP}TCP{R}  {t.sport} → {t.dport} flags={tcp_flags_str(t)} seq={t.seq} ack={t.ack} win={t.window}")
        elif UDP in pkt:
            u = pkt[UDP]
            print(f"       {C.UDP}UDP{R}  {u.sport} → {u.dport} len={u.len}")
        elif ICMP in pkt:
            i = pkt[ICMP]
            print(f"       {C.ICMP}ICMP{R} type={i.type} code={i.code}")
            # type 8 code 0 = Echo request(ping), type 0 code 0 = Echo reply

    # We split IPv4 and IPv6 because some field names and layers differ, even though most of the logic is the same.
    # Ex. for v4 we use 'proto' to get protocols number, but v6 uses 'nh'(next header) to indicate TCP/UDP/ICMPv6
            
    # IPv6
    if IPv6 in pkt:
        ip6 = pkt[IPv6]
        print(f"       {C.IP}IPv6{R} {ip6.src} → {ip6.dst} hlim={ip6.hlim} plen={ip6.plen} nh={ip6.nh}")
        if TCP in pkt:
            t = pkt[TCP]
            print(f"       {C.TCP}TCP{R}  {t.sport} → {t.dport} flags={tcp_flags_str(t)}")
        elif UDP in pkt:
            u = pkt[UDP]
            print(f"       {C.UDP}UDP{R}  {u.sport} → {u.dport} len={u.len}")
        elif pkt.haslayer(ICMPv6EchoRequest):
            i = pkt[ICMPv6EchoRequest]
            print(f"       {C.ICMP}ICMPv6 Echo Req{R} id={i.id} seq={i.seq}")
        elif pkt.haslayer(ICMPv6EchoReply):
            i = pkt[ICMPv6EchoReply]
            print(f"       {C.ICMP}ICMPv6 Echo Rep{R} id={i.id} seq={i.seq}")

# ---------------------- Main ----------------------
def main():
    args = parse_args()
    C, S, R = setup_colors(args.no_color)

    writer = None
    if args.write:
        writer = PcapWriter(args.write, append=True, sync=True)
        # append = True to avoid overwriting, just add packet to the end off the file
        # sync = True to flush to disk immediately, so we dont lose packets if the program is interrupted
        print(f"{C.ETH}* Writing to PCAP:{R} {args.write} (append mode)")

    # Counter
    stats = Counter()  # ADD: counts protocol hits

    # Callback function, its a sniff
    def _cb(pkt):
        
        stats["total"] += 1
        # Light-weight layer checks (adjust to your imports):
        if ARP in pkt:   stats["arp"]  += 1
        if IP in pkt:    stats["ipv4"] += 1
        if IPv6 in pkt:  stats["ipv6"] += 1
        if TCP in pkt:   stats["tcp"]  += 1
        if UDP in pkt:   stats["udp"]  += 1

        print_packet(pkt, C, S, R)
        if writer:
            writer.write(pkt)

    # sniff parameters
    sniff_kwargs = dict(prn=_cb, store=False)
    if args.iface: # What network that i wanna listen to.
        sniff_kwargs["iface"] = args.iface
    if args.filter:
        sniff_kwargs["filter"] = args.filter
    if args.count and args.count > 0:
        sniff_kwargs["count"] = args.count
    if args.timeout and args.timeout > 0:
        sniff_kwargs["timeout"] = args.timeout


    try:
        sniff(**sniff_kwargs)
    except PermissionError:
        print(f"{C.ERR}[!] Permission denied. Run as root/admin (e.g., sudo).{R}")
        # On Linux/macOS, sniffing requires root priviledge.
    except KeyboardInterrupt:
        pass
        # If you press Ctrl+C, Python raises KeyboardInterrupt.
        # This block just ignores it (pass) so the program quits cleanly without a scary traceback.
    finally:
        if writer:
            writer.close()
        # To ensure we dont end up with a corrupted or half-written PCAP
            
        # summary with percentages
        total = stats["total"]
        if total:
            def pct(x):  # helper to format %
                return f"{(x/total*100):.1f}%"
            print(
                f"{C.ETH}* Summary:{R} total={total}\n"
                f"  arp = {stats['arp']} ({pct(stats['arp'])})\n"
                f"  ipv4 = {stats['ipv4']} ({pct(stats['ipv4'])})\n"
                f"  ipv6 = {stats['ipv6']} ({pct(stats['ipv6'])})\n"
                f"  tcp = {stats['tcp']} ({pct(stats['tcp'])})\n"
                f"  udp = {stats['udp']} ({pct(stats['udp'])})"
            )


if __name__ == "__main__":
    main()
    # If we import this script to use in other file, it doesn’t auto-run main(), so you can reuse functions like print_packet() or setup_colors() without starting the sniffer.
