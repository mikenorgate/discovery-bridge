"""Linux raw UDP receive copies with kernel IP reassembly and scoped metadata.

Raw sockets do not compete with Avahi for unicast UDP port 5353. They still
require the router's input policy to admit traffic and CAP_NET_RAW to open.
"""

from ipaddress import ip_address
import socket
import struct

from discovery.observation import Packet

IP_PKTINFO = 8
IP_RECVTTL = 12
IPV6_CHECKSUM = 7


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def decode_udp(data, *, family, source, destination, interface, generation, hop_limit):
    src, dst = ip_address(source), ip_address(destination)
    if src.version != family or dst.version != family or len(data) < 8:
        raise ValueError('invalid UDP envelope')
    sport, dport, size, check = struct.unpack_from('!4H', data)
    if size != len(data) or size > 8960 or size < 20:
        raise ValueError('invalid UDP size')
    pseudo = src.packed + dst.packed
    pseudo += struct.pack('!BBH', 0, 17, size) if family == 4 else struct.pack('!I3xB', size, 17)
    if family == 6 and check == 0:
        raise ValueError('IPv6 requires a UDP checksum')
    if check and checksum(pseudo + data) != 0:
        raise ValueError('invalid UDP checksum')
    return Packet(interface, generation, family, str(src), str(dst), hop_limit, sport, dport, data[8:])


class Receiver:
    def __init__(self, name, interface, generation, family, ipv4_address=None):
        self.interface, self.generation, self.family = interface, generation, family
        af = socket.AF_INET if family == 4 else socket.AF_INET6
        self.socket = socket.socket(af, socket.SOCK_RAW, socket.IPPROTO_UDP)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, name.encode() + b'\0')
            if family == 4:
                self.socket.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
                self.socket.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
                membership = socket.inet_aton('224.0.0.251') + socket.inet_aton(ipv4_address) + struct.pack('@i', interface)
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
            else:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
                self.socket.setsockopt(socket.IPPROTO_IPV6, IPV6_CHECKSUM, 6)
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                                       socket.inet_pton(af, 'ff02::fb') + struct.pack('@I', interface))
            self.socket.setblocking(False)
        except BaseException:
            self.socket.close()
            raise

    def close(self):
        self.socket.close()

    def receive(self):
        data, ancillary, flags, peer = self.socket.recvmsg(9100, 256)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise ValueError('truncated receive data or metadata')
        index = destination = hop = None
        for level, kind, value in ancillary:
            if self.family == 4 and level == socket.IPPROTO_IP:
                if kind == IP_PKTINFO:
                    index = struct.unpack_from('@I', value)[0]
                    destination = socket.inet_ntop(socket.AF_INET, value[8:12])
                elif kind == socket.IP_TTL:
                    hop = struct.unpack('@i', value)[0]
            elif self.family == 6 and level == socket.IPPROTO_IPV6:
                if kind == socket.IPV6_PKTINFO:
                    destination = socket.inet_ntop(socket.AF_INET6, value[:16])
                    index = struct.unpack_from('@I', value, 16)[0]
                elif kind == socket.IPV6_HOPLIMIT:
                    hop = struct.unpack('@i', value)[0]
        if index != self.interface or destination is None or hop is None:
            raise ValueError('missing or mismatched receive metadata')
        source = peer[0]
        if self.family == 4:
            size = (data[0] & 15) * 4 if data else 0
            if size < 20 or len(data) < size or data[0] >> 4 != 4:
                raise ValueError('invalid IPv4 header')
            total = struct.unpack_from('!H', data, 2)[0]
            if total != len(data) or data[9] != 17 or checksum(data[:size]):
                raise ValueError('invalid IPv4 payload/header checksum')
            if struct.unpack_from('!H', data, 6)[0] & 0x3FFF:
                raise ValueError('IP reassembly incomplete')
            data = data[size:]
        return decode_udp(data, family=self.family, source=source, destination=destination,
                          interface=index, generation=self.generation, hop_limit=hop)


class LinkMonitor:
    """Any link/address notification invalidates the collector's topology epoch."""

    def __init__(self):
        self.socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        self.socket.bind((0, 1 | 0x10 | 0x100))
        self.socket.setblocking(False)

    def changed(self):
        try:
            self.socket.recv(65536)
        except BlockingIOError:
            return False
        except OSError:
            return True
        # Overflow, deletion and address changes all require a fresh snapshot.
        return True

    def close(self):
        self.socket.close()


def send_goodbyes(interface, family, signature, addresses):
    """Send only TTL-zero answers, without binding or competing for UDP 5353.

    Avahi 0.8 suppresses goodbyes for duplicate records on other interfaces.
    The independent owner uses these scoped packets after Reset to close that
    gap. Inputs are its already-authorized, already-published record signature.
    """
    import dns.exception
    import dns.flags
    import dns.message
    import dns.name
    import dns.rdata
    import dns.rrset
    packets = []
    message = dns.message.Message(id=0)
    message.flags = dns.flags.QR | dns.flags.AA
    for key, unique in signature:
        name, _ = dns.name.from_wire(key[0], 0)
        data = dns.rdata.from_wire(1, key[1], key[2], 0, len(key[2]))
        rrset = dns.rrset.from_rdata(name, 0, data)
        if unique:
            rrset.rdclass |= 0x8000
        message.answer.append(rrset)
        try:
            message.to_wire(max_size=1232)
        except dns.exception.TooBig:
            message.answer.pop()
            if message.answer:
                packets.append(message.to_wire(max_size=8952))
            message = dns.message.Message(id=0)
            message.flags = dns.flags.QR | dns.flags.AA
            message.answer.append(rrset)
    if message.answer:
        packets.append(message.to_wire(max_size=8952))
    if len(packets) > 256:
        raise ValueError('goodbye packet budget exceeded')
    _send_multicast(interface, family, packets, addresses)


def send_questions(interface, family, name, kinds, addresses):
    """Request fresh evidence when Avahi can satisfy a browse from its cache.

    The collector's admitted, rate-limited demand supplies only a local name
    and supported types. No client packet sections or known answers are copied.
    """
    import dns.message
    from discovery.avahi import local_name, SUPPORTED
    name = local_name(name)
    kinds = tuple(kinds)
    if not kinds or len(kinds) > len(SUPPORTED) or not set(kinds) <= SUPPORTED:
        raise ValueError('unsupported fresh question types')
    message = dns.message.Message(id=0)
    for kind in kinds:
        message.question.extend(dns.message.make_query(name, kind).question)
    _send_multicast(interface, family, [message.to_wire(max_size=1232)], addresses)


def _send_multicast(interface, family, packets, addresses):
    if family not in (4, 6):
        raise ValueError('unsupported multicast family')
    af = socket.AF_INET if family == 4 else socket.AF_INET6
    source = next((a for a in addresses if ip_address(a).version == family and not ip_address(a).is_link_local), None)
    if source is None:
        source = next(a for a in addresses if ip_address(a).version == family)
    destination = '224.0.0.251' if family == 4 else 'ff02::fb'
    with socket.socket(af, socket.SOCK_RAW, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, socket.if_indextoname(interface).encode() + b'\0')
        if family == 4:
            sock.bind((source, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER = DONT
            target = (destination, 0)
        else:
            sock.bind((source, 0, 0, interface))
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_CHECKSUM, 6)
            sock.setsockopt(socket.IPPROTO_IPV6, 23, 0)  # IPV6_MTU_DISCOVER = DONT
            target = (destination, 0, 0, interface)
        for wire in packets:
            size = len(wire) + 8
            udp = struct.pack('!4H', 5353, 5353, size, 0) + wire
            if family == 4:
                pseudo = ip_address(source).packed + ip_address(destination).packed + struct.pack('!BBH', 0, 17, size)
                udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]
            sock.sendto(udp, target)
