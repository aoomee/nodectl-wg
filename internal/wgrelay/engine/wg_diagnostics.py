"""Read-only WireGuard diagnostics; collect header counts, never private keys or payloads."""
import ipaddress
import json
import socket
import struct
import subprocess
import sys
import time

IFACE = 'wg-abauto'


def command(args):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=4)
        return p.stdout.strip() if p.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def udp_header(packet):
    if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != 17:
        return None
    offset = (packet[0] & 15) * 4
    if offset < 20 or len(packet) < offset + 12 or struct.unpack('!H', packet[6:8])[0] & 0x1fff:
        return None
    src, dst = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
    sport, dport, length = struct.unpack('!HHH', packet[offset:offset + 6])
    kind = struct.unpack('<I', packet[offset + 8:offset + 12])[0]
    # Standard WireGuard initiation, response, cookie, or transport packet lengths.
    if not ((kind == 1 and length == 156) or (kind == 2 and length == 100) or
            (kind == 3 and length == 72) or (kind == 4 and length >= 40)):
        return None
    return src, dst, sport, dport, kind


def snapshot():
    public = command(['wg', 'show', IFACE, 'public-key'])
    peers = command(['wg', 'show', IFACE, 'peers']).splitlines()
    endpoint = command(['wg', 'show', IFACE, 'endpoints'])
    stamps = []
    for line in command(['wg', 'show', IFACE, 'latest-handshakes']).splitlines():
        try: stamps.append(int(line.split()[-1]))
        except (ValueError, IndexError): pass
    return {'interface': bool(public), 'public_key': public, 'peers': peers,
            'endpoint': endpoint, 'handshake': max(stamps, default=0),
            'listen_port': command(['wg', 'show', IFACE, 'listen-port']),
            'allowed': command(['wg', 'show', IFACE, 'allowed-ips']),
            'service': command(['systemctl', 'is-active', 'wg-quick@' + IFACE])}


def firewall_counts():
    text = command(['iptables', '-w', '2', '-nvxL', 'WGMR-' + IFACE])
    result = {'available': bool(text), 'accept': 0, 'drop': 0, 'sources': []}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 9 and fields[0].isdigit():
            if fields[2] == 'ACCEPT':
                result['accept'] += int(fields[0]); result['sources'].append(fields[7])
            elif fields[2] == 'DROP': result['drop'] += int(fields[0])
    return result


def collect(c):
    global IFACE
    IFACE = c.get('iface', 'wg-abauto')
    if not __import__('re').fullmatch(r'wg-(?:abauto|s[a-f0-9]{10})', IFACE):
        raise ValueError('invalid interface')
    result = snapshot()
    result['firewall_before'] = firewall_counts()
    result.update(capture=False, incoming=0, outgoing=0, incoming_sources=[], capture_limited=False, flows=[])
    if not result['interface']:
        result['note'] = 'WG 接口尚未建立。'
        return result
    if c['role'] == 'B':
        try: port = int(result['listen_port'])
        except ValueError: port = 0
    else:
        try: port = int(result['endpoint'].split()[-1].rsplit(':', 1)[1])
        except (ValueError, IndexError): port = 0
    result['wg_port'] = port
    if not port:
        result['note'] = '未能读取 WG 监听端口或对端地址。'
        return result
    try: local_port = int(result.get('listen_port', 0))
    except ValueError: local_port = 0
    flows = {}
    capture = None
    ping = None
    sources = set()
    try:
        # ETH_P_ALL is required to see locally transmitted packets as well as ingress.
        # Filter IPv4 UDP headers in udp_header before counting anything.
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
        capture.settimeout(0.3)
        result['capture'] = True
        deadline = time.monotonic() + 14
        trigger = time.monotonic() + 2
        packets = 0
        while time.monotonic() < deadline:
            if c['role'] == 'A' and ping is None and time.monotonic() >= trigger:
                # Traffic on the existing interface prompts WireGuard to retry its handshake.
                try:
                    target = str(ipaddress.ip_interface(result['allowed'].split()[1].split(',')[0]).ip)
                    ping = subprocess.Popen(['ping', '-I', IFACE, '-c', '10', '-i', '1', '-W', '1', target],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except (OSError, ValueError, IndexError):
                    trigger = deadline
            try: packet, address = capture.recvfrom(80)
            except socket.timeout: continue
            packets += 1
            if packets > 50000:
                result['capture_limited'] = True
                break
            header = udp_header(packet)
            if not header: continue
            src, dst, sport, dport, kind = header
            outgoing = address[2] == socket.PACKET_OUTGOING
            if c['role'] == 'B':
                relevant = sport == port if outgoing else dport == port
            else:
                relevant = (dst == c['b_ip'] and dport == port) if outgoing else ((local_port and dport == local_port) or (src == c['b_ip'] and sport == port))
            if relevant:
                flow = (outgoing, src, sport, dst, dport, kind, address[0])
                if flow in flows or len(flows) < 16: flows[flow] = flows.get(flow, 0) + 1
                result['outgoing' if outgoing else 'incoming'] += 1
                if not outgoing and len(sources) < 8: sources.add(src)
    except (OSError, AttributeError) as exc:
        result['note'] = '系统不允许收发采样：' + type(exc).__name__
    finally:
        if capture: capture.close()
        if ping is not None:
            if ping.poll() is None: ping.terminate()
            try: ping.wait(timeout=2)
            except subprocess.TimeoutExpired: ping.kill(); ping.wait()
    result['flows'] = [dict(direction='out' if k[0] else 'in', source=k[1], sport=k[2], destination=k[3], dport=k[4], kind=k[5], device=k[6], count=v) for k,v in flows.items()]
    result['incoming_sources'] = sorted(sources)
    result['firewall_after'] = firewall_counts()
    result['handshake'] = snapshot()['handshake']
    return result


if __name__ == '__main__':
    print(json.dumps(collect(json.loads(sys.argv[1]))))
