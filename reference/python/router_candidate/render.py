"""Render candidate artifacts from operator-reviewed live address JSON; never apply."""
import argparse
import json
from pathlib import Path
from discovery.router_candidate import avahi_config, transaction

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('addresses', help='object keyed by six LAN names, with addresses/prefixes lists')
parser.add_argument('output_directory')
parser.add_argument('--gateway', help='reviewed HTTP admission JSON; omitted means no gateway admission')
args = parser.parse_args()
config = json.loads(Path(args.addresses).read_text())
gateway = json.loads(Path(args.gateway).read_text()) if args.gateway else None
firewall = transaction(config, gateway=gateway)
output = Path(args.output_directory)
output.mkdir(parents=True, exist_ok=True)
(output / 'discovery.nft').write_text(firewall)
(output / 'avahi-daemon.conf').write_text(avahi_config())
