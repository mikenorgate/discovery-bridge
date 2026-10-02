"""Check a complete enabled factory ruleset in isolated native nft namespaces."""
import json,sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'router_factory/scripts'))
import nft_policy
root = Path(sys.argv[1])  # Public factory snapshot with discovery enabled.
policy=json.loads((root/nft_policy.POLICY_PATH).read_text())
text=(root/'mkosi.extra/etc/nftables.conf').read_text()
for name,body in [
 ('enabled_complete_ruleset',text),
 ('mdns_hop_limit_required',text.replace('ip6 hoplimit 255','ip6 hoplimit 254',1)),
 ('mdns_interface_scope_required',text.replace('iifname "lan-vlan1" ip saddr','iifname "wan0" ip saddr',1)),
 ('forwarding_policy_unchanged',text.replace('chain forward_services {','chain forward_services {\n accept',1))]:
 try:
  result=nft_policy.validate(nft_policy.native_rules(body),policy,profile=policy['profile'],mode=policy['mode'])
  assert name=='enabled_complete_ruleset',name+' unexpectedly accepted'
 except nft_policy.FirewallError:
  assert name!='enabled_complete_ruleset'
  assert body!=text
  result={'rejected':True}
 print(json.dumps({'case':name,'status':'pass','result':result}),flush=True)
