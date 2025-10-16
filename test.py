#!/usr/bin/env python3
# Simple scapy-based packet sniffer (captures packets from an interface / BPF filter)
# Requires: scapy (pip3 install scapy)
# Run with root: sudo python3 test.py -i en0 -f "tcp port 80"
import argparse
try:
    from scapy.all import sniff, IP, TCP, Raw  # type: ignore
except Exception:
    import sys
    print("Required dependency 'scapy' not found. Install with: pip3 install scapy", file=sys.stderr)
    sys.exit(1)



def packet_handler(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        summary = f"{src} -> {dst} [{pkt.summary()}]"
        print(summary)

        # If there's a payload, show a short printable preview
        if Raw in pkt:
            try:
                payload = pkt[Raw].load
                # decode best-effort and limit length
                text = payload.decode('utf-8', errors='replace')
                preview = text[:200].replace('\n', r'\n')
                print("  Payload preview:", preview)
            except Exception:
                print("  Payload: <non-decodable bytes>")

def main():
    p = argparse.ArgumentParser(description="scapy packet sniffer")
    p.add_argument('-i', '--iface', default=None, help='interface to sniff (default: scapy chooses)')
    p.add_argument('-f', '--filter', default='ip', help='BPF filter (default: "ip")')
    p.add_argument('-c', '--count', type=int, default=0, help='number of packets to capture (0 = infinite)')
    args = p.parse_args()

    print(f"Starting sniff on iface={args.iface or 'default'} filter='{args.filter}' (ctrl-c to stop)")
    sniff(iface=args.iface, filter=args.filter, prn=packet_handler, store=0, count=args.count)

if __name__ == "__main__":
    main()
