"""Private IPC admission, FD cleanup, renewal and loss of the broker."""
import asyncio
import os
import socket
import time
from types import SimpleNamespace
import unittest

from discovery.node_ipc import Publisher, Sessions, receive, send
from discovery.pod_socket import PodSocket


class IPCTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.owner, self.worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.receiver = Sessions(self.worker, SimpleNamespace())

    async def asyncTearDown(self):
        self.owner.close()
        await self.receiver.close()

    async def test_live_ping_does_not_renew_eligibility(self):
        lease = SimpleNamespace(deadline=123)
        self.receiver.sessions['pod'] = lease
        before = self.receiver.last_ping
        self.receiver.apply({'op': 'ping'}, [])
        self.assertGreaterEqual(self.receiver.last_ping, before)
        self.assertEqual(lease.deadline, 123)
        self.receiver.sessions.clear()

    async def test_unknown_messages_and_stale_tokens_rejected(self):
        for value in ({'op': 'enter', 'pid': 1}, {'op': 'ping', 'extra': True},
                      {'op': 'renew', 'uid': 'pod', 'token': 'a' * 32, 'deadline': time.monotonic() + 10}):
            with self.assertRaises(ValueError): self.receiver.apply(value, [])

    async def test_rejected_message_closes_received_descriptors(self):
        read, write = os.pipe()
        try:
            send(self.owner, {'op': 'ping'}, [read])
            value, descriptors = receive(self.worker)
            copy = descriptors[0]
            self.assertFalse(os.get_inheritable(copy))
            with self.assertRaises(ValueError): self.receiver.apply(value, descriptors)
            with self.assertRaises(OSError): os.fstat(copy)
        finally:
            os.close(read); os.close(write)

    async def test_oversize_packet_rejected_without_retaining_descriptors(self):
        self.owner.send(b' ' * 9000)
        with self.assertRaises(ValueError): receive(self.worker)

    async def test_invalid_adopted_socket_is_closed(self):
        wrong = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with self.assertRaises(ValueError):
            PodSocket.adopt(wrong, {'index': 1, 'family': 4, 'addresses': ['192.0.2.2']})
        self.assertEqual(wrong.fileno(), -1)

    async def test_broker_eof_stops_receiver(self):
        self.owner.close()
        with self.assertRaises(EOFError): await self.receiver.run()
        self.assertTrue(self.receiver.closed)

    async def test_missing_heartbeat_stops_receiver(self):
        self.receiver.last_ping = time.monotonic() - 6
        with self.assertRaises(TimeoutError): await self.receiver.run()
        self.assertTrue(self.receiver.closed)

    async def test_publisher_renews_without_resending_descriptors(self):
        publisher = Publisher(self.owner)
        publisher.sent['pod'] = 'a' * 32
        lease = SimpleNamespace(token='a' * 32, deadline=time.monotonic() + 20)
        publisher.renew({'pod': lease})
        value, descriptors = receive(self.worker)
        self.assertEqual(value, {'op': 'ping'})
        self.assertEqual(descriptors, [])
        value, descriptors = receive(self.worker)
        self.assertEqual(value['op'], 'renew')
        self.assertEqual(descriptors, [])
