"""Render review-only discovery chains for the router's existing filter table.

No subprocess, nft apply, forwarding accept or inventory enforcement occurs.
Integrate jumps after source-safety checks and before default deny in G5.
"""
from ipaddress import ip_address, ip_network
import re

VLANS = (1, 11, 22, 23, 55, 98)


def factory_projection(config):
    """Public signed feature input; disabled is the only implicit profile."""
    if config == {'enabled': False} and type(config['enabled']) is bool:
        return {'enabled': False, 'runtime': {'enabled': False}, 'incoming': (), 'outgoing': ()}
    if (set(config) - {'translation', 'publication'} != {'enabled', 'links', 'gateway', 'forbidden'}
            or config['enabled'] is not True or type(config.get('translation', False)) is not bool):
        raise ValueError('explicit complete discovery profile required')
    incoming, outgoing = rules(config['links'])
    gate_in, gate_out = gateway_rules(config['gateway'])
    for link in config['links'].values():
        if set(link) != {'addresses', 'prefixes'} or not 1 <= len(link['addresses']) <= 16 or not 1 <= len(link['prefixes']) <= 16:
            raise ValueError('bounded discovery link addresses and prefixes required')
        if any(ip_address(a).is_unspecified or ip_address(a).is_multicast or ip_address(a).is_loopback for a in link['addresses']):
            raise ValueError('invalid discovery interface address')
        if any(ip_network(n).prefixlen == 0 or ip_network(n).is_multicast or ip_network(n).is_loopback for n in link['prefixes']):
            raise ValueError('invalid discovery source prefix')
    if config['gateway']['address'] not in {a for link in config['links'].values() for a in link['addresses']}:
        raise ValueError('gateway must bind a reviewed router interface address')
    if not isinstance(config['forbidden'], list) or not 1 <= len(config['forbidden']) <= 128:
        raise ValueError('explicit forbidden address ranges required')
    for prefix in config['forbidden']:
        ip_network(prefix)
    runtime = {'enabled': True, 'interfaces': list(config['links']),
               'prefixes': {name: link['prefixes'] for name, link in config['links'].items()},
               'forbidden': config['forbidden'],
               'bootstrap': [['_esphomelib._tcp.local.', 12], ['_home-assistant._tcp.local.', 12]],
               'gateway': {'enabled': True, 'listen_address': config['gateway']['address'],
                           'port': config['gateway']['port'], 'clients': config['gateway']['clients']}}
    if config.get('translation'):
        runtime['translation'] = True
    if 'publication' in config:
        publication = config['publication']
        extra_in, extra_out = gateway_rules(publication)
        if (publication['address'] != config['gateway']['address']
                or publication['port'] == config['gateway']['port']):
            raise ValueError('publication requires a separate port on the gateway address')
        gate_in += extra_in
        gate_out += extra_out
        runtime['publication'] = {'enabled': True, 'listen_address': publication['address'],
                                  'port': publication['port'], 'clients': publication['clients']}
    return {'enabled': True, 'runtime': runtime, 'incoming': incoming + gate_in,
            'outgoing': outgoing + gate_out, 'avahi': avahi_config()}


def rules(config):
    input_rules, output_rules = [], []
    if set(config) != {f'lan-vlan{v}' for v in VLANS}:
        raise ValueError('candidate requires the six explicit production LANs')
    for name, values in config.items():
        for family in (4, 6):
            addresses = [ip_address(a) for a in values['addresses'] if ip_address(a).version == family]
            networks = [ip_network(n) for n in values['prefixes'] if ip_network(n).version == family]
            if not addresses:
                continue
            if not networks or any(not any(a in n for n in networks) and not a.is_link_local for a in addresses):
                raise ValueError('assigned address lacks an approved LAN prefix')
            proto, ttl = ('ip', 'ttl') if family == 4 else ('ip6', 'hoplimit')
            group = '224.0.0.251' if family == 4 else 'ff02::fb'
            sources = ', '.join(map(str, networks)) + (', fe80::/10' if family == 6 else '')
            local = ', '.join(map(str, addresses))
            input_rules.append(f'iifname "{name}" {proto} saddr {{ {sources} }} {proto} daddr {{ {group}, {local} }} {proto} {ttl} 255 udp dport 5353 counter accept')
            # Includes QU replies and legacy clients using an ephemeral port.
            output_rules.append(f'oifname "{name}" {proto} saddr {{ {local} }} {proto} daddr {{ {group}, {sources} }} {proto} {ttl} 255 udp sport 5353 counter accept')
            if family == 4:
                membership = 'ip daddr 224.0.0.0/4 ip ttl 1 ip protocol igmp'
            else:
                membership = 'ip6 saddr { ::, fe80::/10 } ip6 daddr ff02::/16 ip6 hoplimit 1 meta l4proto ipv6-icmp icmpv6 type { 130, 131, 132, 143 }'
            input_rules.append(f'iifname "{name}" {membership} counter accept')
            output_rules.append(f'oifname "{name}" {membership} counter accept')
    return tuple(input_rules), tuple(output_rules)


def gateway_rules(config):
    """Explicit HTTP admission for reviewed routed node sources, never mDNS."""
    if set(config) != {'interfaces', 'address', 'clients', 'port'}:
        raise ValueError('explicit gateway interface/address/client/port policy required')
    address = ip_address(config['address'])
    clients = tuple(ip_network(value) for value in config['clients'])
    interfaces = config['interfaces']
    port = config['port']
    if (not interfaces or set(interfaces) - {f'lan-vlan{v}' for v in VLANS}
            or not clients or len(clients) > 32 or type(port) is not int or not 1024 <= port <= 65535
            or address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local
            or any(n.version != address.version or n.prefixlen == 0 or n.is_multicast or n.is_loopback
                   or n.is_link_local or n.network_address.is_unspecified for n in clients)):
        raise ValueError('invalid scoped gateway policy')
    proto = 'ip' if address.version == 4 else 'ip6'
    sources = ', '.join(map(str, clients))
    incoming = tuple(f'iifname "{name}" {proto} saddr {{ {sources} }} {proto} daddr {address} tcp dport {port} counter accept'
                     for name in interfaces)
    outgoing = tuple(f'oifname "{name}" {proto} saddr {address} {proto} daddr {{ {sources} }} tcp sport {port} ct state established counter accept'
                     for name in interfaces)
    return incoming, outgoing


def transaction(config, *, table='example_router_factory', gateway=None):
    if not re.fullmatch('[a-zA-Z_][a-zA-Z0-9_]*', table):
        raise ValueError('invalid table identifier')
    incoming, outgoing = rules(config)
    if gateway is not None:
        extra_in, extra_out = gateway_rules(gateway)
        incoming += extra_in
        outgoing += extra_out
    lines = [f'add chain inet {table} discovery_input', f'add chain inet {table} discovery_output']
    lines += [f'add rule inet {table} discovery_input {rule}' for rule in incoming]
    lines += [f'add rule inet {table} discovery_output {rule}' for rule in outgoing]
    # Existing base-chain input_safety/output_safety still run before these.
    lines += [f'insert rule inet {table} input_local_services jump discovery_input comment "g1-discovery-candidate"',
              f'insert rule inet {table} output_local_services jump discovery_output comment "g1-discovery-candidate"']
    return '\n'.join(lines) + '\n'


def avahi_config():
    names = ','.join(f'lan-vlan{v}' for v in VLANS)
    return ('[server]\nuse-ipv4=yes\nuse-ipv6=yes\nenable-dbus=yes\nentries-per-entry-group-max=4096\nallow-interfaces=' + names + '\n'
            '[wide-area]\nenable-wide-area=no\n[publish]\npublish-addresses=no\npublish-hinfo=no\n'
            'publish-workstation=no\npublish-domain=no\n[reflector]\nenable-reflector=no\n')
