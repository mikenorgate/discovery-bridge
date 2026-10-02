"""Compare local publication frames with the maintained Python boundary."""
from contextlib import closing
import json
import sys

from discovery.avahi import Link
from discovery.identity import Identities
from discovery.publication import decode, frame

request = json.load(sys.stdin)
with closing(Identities(request["state"])) as identities:
    sequence, groups = decode(
        request["frame"].encode(), now=0.5, previous=0,
        links={2: Link("lan-a", "link-a", frozenset({4, 6}))},
        owns=identities.owns, owns_host=identities.owns_host,
    )
    records = sorted(
        [answer.name.canonicalize().to_wire().hex(), int(answer.type),
         answer.data.to_digestable().hex(), answer.source, answer.unique,
         answer.ttl]
        for answer in groups[0].records
    )
    print(json.dumps({"sequence": sequence, "records": records,
                      "frame": frame(groups, sequence=sequence, now=0).decode()}))
