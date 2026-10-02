"""Authorized, bounded question-only LAN lookup requests; no publication API."""
import asyncio
import json
import math
import time

import dns.exception
import dns.name
import dns.rdatatype as rt

from discovery.catalog import _fields, _object
from discovery.query import Question

MAX_LOOKUP_BYTES = 16384
LOOKUP_TYPES = frozenset((rt.A, rt.AAAA, rt.PTR, rt.SRV, rt.TXT, rt.ANY))


class Busy(ValueError):
    pass


def decode_lookup(payload):
    if not 1 <= len(payload) <= MAX_LOOKUP_BYTES:
        raise ValueError('lookup size limit')
    try:
        value = json.loads(payload.decode('utf-8'), object_pairs_hook=_object)
        _fields(value, {'schema', 'questions'})
        if type(value['schema']) is not int or value['schema'] != 1:
            raise ValueError('unsupported lookup schema')
        if not isinstance(value['questions'], list) or not 1 <= len(value['questions']) <= 16:
            raise ValueError('lookup question limit')
        questions = []
        for entry in value['questions']:
            _fields(entry, {'name', 'type', 'class'})
            if type(entry['type']) is not int or entry['type'] not in LOOKUP_TYPES:
                raise ValueError('unsupported LAN lookup type')
            if type(entry['class']) is not int or entry['class'] != 1:
                raise ValueError('lookup class must be IN')
            if not isinstance(entry['name'], str) or not 1 <= len(entry['name'].encode()) <= 1024:
                raise ValueError('invalid lookup name')
            name = dns.name.from_text(entry['name'].encode('utf-8'), origin=None)
            if not name.is_absolute() or not name.is_subdomain(dns.name.from_text('local.')):
                raise ValueError('lookup must be an absolute local name')
            questions.append(Question(name.canonicalize().to_text(), entry['type']))
        if len(set(questions)) != len(questions):
            raise ValueError('duplicate lookup question')
        return tuple(questions)
    except (UnicodeError, RecursionError, dns.exception.DNSException, TypeError) as exc:
        raise ValueError('invalid lookup encoding') from exc


class Bucket:
    def __init__(self, rate, burst):
        if rate <= 0 or burst < 1 or not math.isfinite(rate) or not math.isfinite(burst):
            raise ValueError('invalid rate limit')
        self.rate, self.burst, self.tokens, self.updated = rate, burst, float(burst), None
        self.failed = False

    def take(self, now, cost=1):
        if not math.isfinite(now) or (self.updated is not None and now < self.updated):
            self.failed = True
        if self.failed:
            return False
        if self.updated is not None:
            self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if cost > self.tokens:
            return False
        self.tokens -= cost
        return True


class LookupCoordinator:
    """Coalesce admitted nodes' questions over the shared approved LAN sources.

    The callback requests LAN browsing. Its completion is not a DNS answer or
    proof that a name does not exist. All records arrive through the collector.
    """
    def __init__(self, sources, demand, *, clock=time.monotonic,
                 global_rate=32, global_burst=128, max_pending=64, cooldown=1, timeout=2):
        if not 1 <= max_pending <= 256 or not 0 <= cooldown <= 5 or not 0 < timeout <= 3:
            raise ValueError('invalid lookup work limits')
        if isinstance(sources, str) or not sources or any(not isinstance(s, str) or not s for s in sources):
            raise ValueError("explicit source links required")
        self.sources = frozenset(sources)
        self.demand, self.clock = demand, clock
        self.global_bucket = Bucket(global_rate, global_burst)
        self.max_pending, self.cooldown, self.timeout = max_pending, cooldown, timeout
        self.pending, self.recent = {}, {}

    async def submit(self, payload):
        sources = self.sources
        questions = decode_lookup(payload)
        now = self.clock()
        # Charge before coalescing: repeated identical requests are still work.
        if not self.global_bucket.take(now, len(questions)):
            raise Busy('lookup rate exceeded')
        self.recent = {key: end for key, end in self.recent.items() if now < end}
        keys = questions
        new = [key for key in keys if key not in self.pending and key not in self.recent]
        if len(self.pending) + len(new) > self.max_pending:
            raise Busy('lookup concurrency exceeded')
        for key in new:
            task = asyncio.create_task(self._run(key, sources))
            task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
            self.pending[key] = task
        tasks = [self.pending[key] for key in keys if key in self.pending]
        if tasks:
            # One disconnected/cancelled client cannot cancel shared LAN work.
            await asyncio.gather(*(asyncio.shield(task) for task in tasks))
        return len(questions)

    async def _run(self, key, sources):
        try:
            async with asyncio.timeout(self.timeout):
                await self.demand(key, sources)
            return True
        finally:
            self.pending.pop(key, None)
            self.recent[key] = self.clock() + self.cooldown
            while len(self.recent) > 512:
                del self.recent[next(iter(self.recent))]

    async def close(self):
        tasks = tuple(self.pending.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.pending.clear()
        self.recent.clear()
