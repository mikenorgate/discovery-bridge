"""Node admission, shared sources and bounded question-only LAN demand."""
import asyncio
import unittest

from discovery.feed import encode
from discovery.lookup import Bucket, Busy, LookupCoordinator, decode_lookup


def request(name='sensor.local.', **extra):
    return encode({'schema': 1, 'questions': [{'name': name, 'type': 1, 'class': 1}], **extra})


class LookupDecoderTests(unittest.TestCase):
    def test_question_only_schema_and_local_names(self):
        self.assertEqual(decode_lookup(request('SENSOR.local.'))[0].name, 'sensor.local.')
        for payload in [request(view='all'), request(records=[]), request(pod='198.18.22.2'),
                        request('outside.example.'), request('relative'), request('a' * 64 + '.local.'),
                        request().replace(b'"type":1', b'"type":true'),
                        request().replace(b'"schema":1', b'"schema":1,"schema":1'),
                        b' ' * 16385, b'\xff', b'[' * 2000,
                        encode({'schema': 1, 'questions': []})]:
            with self.subTest(payload=payload[:100]), self.assertRaises(ValueError):
                decode_lookup(payload)

    def test_duplicate_questions_and_limits(self):
        question = {'name': 'sensor.local.', 'type': 1, 'class': 1}
        for count in (2, 17):
            with self.assertRaises(ValueError):
                decode_lookup(encode({'schema': 1, 'questions': [question] * count}))

    def test_bucket_clock_rollback_latches_closed(self):
        bucket = Bucket(1, 2)
        self.assertTrue(bucket.take(100, 2))
        self.assertFalse(bucket.take(100))
        self.assertTrue(bucket.take(101))
        self.assertFalse(bucket.take(99))
        self.assertFalse(bucket.take(200))


class LookupWorkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.calls, self.tick = [], 100
        self.release = asyncio.Event()
        async def demand(question, sources):
            self.calls.append((question, sources))
            await self.release.wait()
        self.worker = LookupCoordinator({'vlan22', 'vlan55'}, demand, clock=lambda: self.tick)

    async def asyncTearDown(self):
        await self.worker.close()

    async def start(self, payload=None):
        task = asyncio.create_task(self.worker.submit(payload or request()))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return task

    async def test_cross_node_coalescing_and_disconnect(self):
        first = await self.start()
        second = await self.start()
        other = await self.start()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][1], {'vlan22', 'vlan55'})
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        self.release.set()
        self.assertEqual(await second, 1)
        self.assertEqual(await other, 1)
        self.assertFalse(self.worker.pending)
        await self.worker.submit(request())
        self.assertEqual(len(self.calls), 1)  # cooldown does not schedule LAN work

    async def test_rate_limit_charged_even_when_coalesced(self):
        self.worker.global_bucket = Bucket(1, 2)
        self.release.set()
        await self.worker.submit(request())
        await self.worker.submit(request())
        with self.assertRaises(Busy):
            await self.worker.submit(request())
        self.assertEqual(len(self.calls), 1)

    async def test_global_limit_and_pending_capacity(self):
        self.worker.max_pending = 1
        first = await self.start()
        with self.assertRaises(Busy):
            await self.worker.submit(request('another.local.'))
        self.assertEqual(len(self.calls), 1)
        self.release.set()
        await first
        self.worker.global_bucket = Bucket(1, 1)
        await self.worker.submit(request())
        with self.assertRaises(Busy):
            await self.worker.submit(request())

    async def test_timeout_and_invalid_input_do_not_leak_tasks(self):
        self.worker.timeout = .01
        with self.assertRaises(TimeoutError):
            await self.worker.submit(request())
        self.assertFalse(self.worker.pending)
        with self.assertRaises(ValueError):
            await self.worker.submit(request(records=[]))
        self.assertEqual(len(self.calls), 1)
