# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


"""Tests for SCRAM channel binding (SCRAM-SHA-256-PLUS) support.

The protocol-level tests in this module talk to a tiny in-process mock
PostgreSQL server instead of a managed cluster, so they run without a
PostgreSQL installation.  The mock server speaks just enough of the
startup/SASL wire protocol to:

* advertise arbitrary SASL mechanism lists over plain and direct TLS;
* fully verify the SCRAM exchange (including the ``c=`` channel
  binding attribute and the client proof) with a reference
  implementation;
* request cleartext/MD5 authentication;
* tear the connection down mid-negotiation.
"""

import asyncio
import base64
import hashlib
import hmac
import os
import re
import ssl
import struct
import unittest

import asyncpg
from asyncpg import connect_utils
from asyncpg import exceptions
from asyncpg.connect_utils import ChannelBinding
from asyncpg.protocol.protocol import (
    SCRAMAuthentication,
    _build_tls_server_end_point_binding,
    _read_x509_signature_algorithm_oid,
)


CERTS = os.path.join(os.path.dirname(__file__), 'certs')
SSL_CERT_FILE = os.path.join(CERTS, 'server.cert.pem')
SSL_KEY_FILE = os.path.join(CERTS, 'server.key.pem')

USER = 'scramuser'
PASSWORD = 'correct horse battery staple'
SALT = b'asyncpg-test-salt'
ITERATIONS = 4096
MD5_SALT = b'\x01\x02\x03\x04'

SCRAM_SHA_256 = b'SCRAM-SHA-256'
SCRAM_SHA_256_PLUS = b'SCRAM-SHA-256-PLUS'
DEFAULT_MECHANISMS = (SCRAM_SHA_256_PLUS, SCRAM_SHA_256)
SSL_REQUEST = struct.pack('!ll', 8, 80877103)


def _pem_to_der(path):
    with open(path, 'rb') as f:
        raw = f.read()
    body = b''.join(
        line for line in raw.splitlines()
        if not line.startswith(b'-----'))
    return base64.b64decode(body)


SERVER_CERT_DER = _pem_to_der(SSL_CERT_FILE)


def _i32(value):
    return value.to_bytes(4, 'big', signed=True)


def _message(mtype, payload):
    return mtype + (len(payload) + 4).to_bytes(4, 'big') + payload


def _hmac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def _salted_password(password, salt, iterations):
    return hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt, iterations)


def _server_verify_scram(mech, initial, final, tls_cert_der):
    """Verify a complete SCRAM client exchange.

    Returns the ``server-final`` message payload on success and raises
    AssertionError if the client proof or channel binding data is wrong.
    """
    first_bare = initial[initial.index(b'n='):]
    client_nonce = re.search(rb'r=([^,]+)', first_bare).group(1)
    nonce = client_nonce + b'-server'
    server_first = (
        b'r=' + nonce + b',s=' + base64.b64encode(SALT)
        + b',i=' + str(ITERATIONS).encode())

    attrs = {}
    for part in final.split(b','):
        key, _, value = part.partition(b'=')
        attrs[key] = value

    if mech == SCRAM_SHA_256_PLUS:
        assert initial.startswith(b'p=tls-server-end-point,,')
        expected_cbind = (
            b'p=tls-server-end-point,,'
            + _build_tls_server_end_point_binding(tls_cert_der))
    elif initial.startswith(b'y,,'):
        expected_cbind = b'y,,'
    elif initial.startswith(b'n,,'):
        expected_cbind = b'n,,'
    else:
        raise AssertionError(
            'unexpected GS2 header: {!r}'.format(initial[:20]))

    c_attr = attrs[b'c']
    assert base64.b64decode(c_attr) == expected_cbind, \
        'channel binding attribute mismatch'
    assert attrs[b'r'] == nonce, 'nonce mismatch'
    proof = base64.b64decode(attrs[b'p'])

    salted = _salted_password(PASSWORD, SALT, ITERATIONS)
    client_key = _hmac(salted, b'Client Key')
    stored_key = hashlib.sha256(client_key).digest()
    server_key = _hmac(salted, b'Server Key')
    auth_message = (
        first_bare + b',' + server_first + b',c=' + c_attr
        + b',r=' + nonce)

    client_signature = _hmac(stored_key, auth_message)
    recovered_client_key = bytes(
        a ^ b for a, b in zip(proof, client_signature))
    assert hashlib.sha256(recovered_client_key).digest() == stored_key, \
        'client proof mismatch'

    server_signature = _hmac(server_key, auth_message)
    return b'v=' + base64.b64encode(server_signature)


class _SSLUpgradeProtocol(asyncio.Protocol):
    """Raw protocol implementing the PostgreSQL SSLRequest dance.

    Accepts the 8-byte SSLRequest in plaintext, answers ``S`` and then
    upgrades the connection to TLS in place (like a real server), before
    handing the decrypted stream to the regular handler.
    """

    def __init__(self, loop, ssl_ctx, on_upgraded):
        self._loop = loop
        self._ssl_ctx = ssl_ctx
        self._on_upgraded = on_upgraded
        self._transport = None
        self._upgraded = False
        self._pending = b''
        self._task = None

    def connection_made(self, transport):
        self._transport = transport

    def data_received(self, data):
        if self._upgraded:
            return
        if data == SSL_REQUEST and not self._pending:
            self._transport.write(b'S')
            self._task = asyncio.ensure_future(
                self._upgrade(), loop=self._loop)
        else:
            # App data can be delivered before start_tls resolves;
            # stash and replay it onto the upgraded protocol.
            self._pending += data

    async def _upgrade(self):
        new_transport = await self._loop.start_tls(
            self._transport, self, self._ssl_ctx, server_side=True)
        self._upgraded = True
        reader = asyncio.StreamReader(loop=self._loop)
        stream_protocol = asyncio.StreamReaderProtocol(
            reader, loop=self._loop)
        new_transport.set_protocol(stream_protocol)
        stream_protocol.connection_made(new_transport)
        if self._pending:
            stream_protocol.data_received(self._pending)
            self._pending = b''
        writer = asyncio.StreamWriter(
            new_transport, stream_protocol, reader, self._loop)
        await self._on_upgraded(reader, writer)

    def connection_lost(self, exc):
        if self._task is not None:
            self._task.cancel()


class FakePostgresServer:
    """A minimal PostgreSQL server exercising authentication paths."""

    def __init__(self, *, use_tls, mechanisms=None,
                 auth='sasl', drop_after_initial=False):
        # A real PostgreSQL server only advertises the -PLUS mechanism
        # on encrypted connections.
        if mechanisms is None:
            if use_tls:
                mechanisms = DEFAULT_MECHANISMS
            else:
                mechanisms = (SCRAM_SHA_256,)
        self.use_tls = use_tls
        self.mechanisms = list(mechanisms)
        self.auth = auth
        self.drop_after_initial = drop_after_initial
        self.connections = 0
        self.events = []
        self.server = None
        self.port = None

    def _server_ssl_context(self):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(SSL_CERT_FILE, SSL_KEY_FILE)
        return ssl_ctx

    async def start(self, *, ssl_upgrade=False):
        if ssl_upgrade:
            loop = asyncio.get_running_loop()
            ssl_ctx = self._server_ssl_context()
            self.server = await loop.create_server(
                lambda: _SSLUpgradeProtocol(
                    loop, ssl_ctx, self.handle),
                '127.0.0.1', 0)
        else:
            ssl_ctx = None
            if self.use_tls:
                ssl_ctx = self._server_ssl_context()
            self.server = await asyncio.start_server(
                self.handle, '127.0.0.1', 0, ssl=ssl_ctx)
        self.port = self.server.sockets[0].getsockname()[1]

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _read_startup(self, reader):
        # The StartupMessage has no type byte: just an int32 length
        # prefix that includes itself.
        header = await reader.readexactly(4)
        length = int.from_bytes(header, 'big')
        return await reader.readexactly(length - 4)

    async def _read_message(self, reader):
        # Regular messages: single-byte type followed by the same
        # int32 length framing.
        mtype = await reader.readexactly(1)
        header = await reader.readexactly(4)
        length = int.from_bytes(header, 'big')
        payload = await reader.readexactly(length - 4)
        return mtype, payload

    async def _send_ready(self, writer):
        writer.write(_message(b'R', _i32(0)))  # AuthenticationOk
        writer.write(_message(
            b'S', b'server_version\x0016.0\x00'))
        writer.write(_message(
            b'K', _i32(1234) + _i32(5678)))  # BackendKeyData
        writer.write(_message(b'Z', b'I'))  # ReadyForQuery, idle

    async def _handle_sasl(self, reader, writer, event):
        payload = _i32(10)
        for mechanism in self.mechanisms:
            payload += mechanism + b'\x00'
        payload += b'\x00'
        writer.write(_message(b'R', payload))  # AuthenticationSASL
        await writer.drain()

        _, body = await self._read_message(reader)
        mechanism, rest = body.split(b'\x00', 1)
        initial_len = int.from_bytes(rest[:4], 'big')
        initial = rest[4:4 + initial_len]
        event['mechanism'] = mechanism
        event['initial'] = initial

        if self.drop_after_initial:
            writer.close()
            return

        first_bare = initial[initial.index(b'n='):]
        client_nonce = re.search(
            rb'r=([^,]+)', first_bare).group(1)
        nonce = client_nonce + b'-server'
        server_first = (
            b'r=' + nonce + b',s=' + base64.b64encode(SALT)
            + b',i=' + str(ITERATIONS).encode())
        writer.write(
            _message(b'R', _i32(11) + server_first))
        await writer.drain()

        _, final = await self._read_message(reader)
        event['final'] = final
        server_final = _server_verify_scram(
            mechanism, initial, final, SERVER_CERT_DER)
        event['verified'] = True
        writer.write(
            _message(b'R', _i32(12) + server_final))
        await self._send_ready(writer)
        await writer.drain()

    async def _handle_password(self, reader, writer, event):
        if self.auth == 'md5':
            writer.write(_message(b'R', _i32(5) + MD5_SALT))
        else:
            writer.write(_message(b'R', _i32(3)))
        await writer.drain()

        _, response = await self._read_message(reader)
        event['password_response'] = response
        await self._send_ready(writer)
        await writer.drain()

    async def handle(self, reader, writer):
        self.connections += 1
        event = {'tls': writer.get_extra_info('ssl_object') is not None}
        self.events.append(event)
        try:
            await self._read_startup(reader)  # StartupMessage
            if self.auth == 'sasl':
                await self._handle_sasl(reader, writer, event)
            else:
                await self._handle_password(reader, writer, event)
            # Stay connected until the client sends Terminate ('X')
            # or hangs up; a real PostgreSQL server closes the socket
            # immediately after receiving Terminate.  Answer simple and
            # extended queries (e.g. the pool reset query) with a bare
            # command completion and a fresh ReadyForQuery.
            while True:
                mtype, _payload = await self._read_message(reader)
                if mtype == b'X':
                    break
                if mtype == b'P':  # Parse
                    writer.write(_message(b'1', b''))
                elif mtype == b'B':  # Bind
                    writer.write(_message(b'2', b''))
                elif mtype == b'E':  # Execute
                    writer.write(_message(b'C', b'RESET 0\x00'))
                elif mtype == b'Q':  # simple Query
                    writer.write(_message(b'C', b'RESET 0\x00'))
                    writer.write(_message(b'Z', b'I'))
                elif mtype == b'S':  # Sync
                    writer.write(_message(b'Z', b'I'))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


def _client_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class TestSCRAMMessages(unittest.TestCase):
    """Unit tests for message construction without a server."""

    def test_plain_gs2_header(self):
        scram = SCRAMAuthentication(SCRAM_SHA_256)
        self.assertEqual(scram.gs2_header, b'n,,')
        self.assertEqual(scram.client_channel_binding, b'n,,')

    def test_supports_channel_binding_gs2_header(self):
        scram = SCRAMAuthentication(
            SCRAM_SHA_256, supports_channel_binding=True)
        self.assertEqual(scram.gs2_header, b'y,,')
        self.assertEqual(scram.client_channel_binding, b'y,,')

    def test_plus_gs2_header_and_cbind_data(self):
        scram = SCRAMAuthentication(
            SCRAM_SHA_256_PLUS, channel_binding_data=b'CB!')
        self.assertEqual(
            scram.gs2_header, b'p=tls-server-end-point,,')
        self.assertEqual(
            scram.client_channel_binding,
            b'p=tls-server-end-point,,CB!')

    def test_plus_requires_channel_binding_data(self):
        with self.assertRaises(ValueError):
            SCRAMAuthentication(SCRAM_SHA_256_PLUS)

    def test_canonical_c_attributes(self):
        self.assertEqual(
            base64.b64encode(
                SCRAMAuthentication(SCRAM_SHA_256).client_channel_binding),
            b'biws')
        self.assertEqual(
            base64.b64encode(
                SCRAMAuthentication(
                    SCRAM_SHA_256,
                    supports_channel_binding=True).client_channel_binding),
            b'eSws')

    def _run_reference_exchange(self, scram):
        """Drive one SCRAM exchange and verify it against the reference."""
        first = scram.create_client_first_message(USER)
        initial = first.split(b'\x00', 1)[1][4:]
        first_bare = initial[initial.index(b'n='):]
        client_nonce = re.search(
            rb'r=([^,]+)', first_bare).group(1)
        nonce = client_nonce + b'-server'
        server_first = (
            b'r=' + nonce + b',s=' + base64.b64encode(SALT)
            + b',i=' + str(ITERATIONS).encode())
        scram.parse_server_first_message(server_first)
        final = scram.create_client_final_message(PASSWORD)
        server_final = _server_verify_scram(
            scram.authentication_method, initial, final, SERVER_CERT_DER)
        self.assertTrue(
            scram.verify_server_final_message(server_final))

    def test_full_exchange_plain_and_plus(self):
        # Reference server-side check of all three variants, exercising
        # the exported cpdef message methods end to end.
        self._run_reference_exchange(
            SCRAMAuthentication(SCRAM_SHA_256))
        self._run_reference_exchange(
            SCRAMAuthentication(
                SCRAM_SHA_256, supports_channel_binding=True))
        self._run_reference_exchange(
            SCRAMAuthentication(
                SCRAM_SHA_256_PLUS,
                channel_binding_data=_build_tls_server_end_point_binding(
                    SERVER_CERT_DER)))


class TestTLSServerEndPointHash(unittest.TestCase):
    """Certificate hash selection per RFC 5929 / libpq rules."""

    def test_test_server_certificate_is_sha256(self):
        self.assertEqual(
            _read_x509_signature_algorithm_oid(SERVER_CERT_DER),
            '1.2.840.113549.1.1.11')
        self.assertEqual(
            _build_tls_server_end_point_binding(SERVER_CERT_DER),
            hashlib.sha256(SERVER_CERT_DER).digest())

    def test_signature_algorithm_hash_selection(self):
        try:
            import datetime
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            self.skipTest('cryptography is not installed')

        def cert_der(signature_hash, key):
            name = x509.Name(
                [x509.NameAttribute(x509.NameOID.COMMON_NAME,
                                    'localhost')])
            builder = (
                x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(datetime.datetime(2020, 1, 1))
                .not_valid_after(datetime.datetime(2030, 1, 1))
                .sign(private_key=key, algorithm=signature_hash))
            return builder.public_bytes(serialization.Encoding.DER)

        cases = (
            (hashes.SHA256(), 'sha256', '1.2.840.113549.1.1.11'),
            (hashes.SHA384(), 'sha384', '1.2.840.113549.1.1.12'),
            (hashes.SHA512(), 'sha512', '1.2.840.113549.1.1.13'),
        )
        for signature_hash, digest_name, oid in cases:
            with self.subTest(digest=digest_name):
                key = rsa.generate_private_key(65537, 2048)
                der = cert_der(signature_hash, key)
                self.assertEqual(
                    _read_x509_signature_algorithm_oid(der), oid)
                self.assertEqual(
                    _build_tls_server_end_point_binding(der),
                    hashlib.new(digest_name, der).digest())

        ecdsa_key = ec.generate_private_key(ec.SECP256R1())
        der = cert_der(hashes.SHA256(), ecdsa_key)
        self.assertEqual(
            _read_x509_signature_algorithm_oid(der),
            '1.2.840.10045.4.3.2')
        self.assertEqual(
            _build_tls_server_end_point_binding(der),
            hashlib.sha256(der).digest())

    def test_weak_and_unknown_signatures_fall_back_to_sha256(self):
        try:
            import datetime
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            self.skipTest('cryptography is not installed')

        # Ed25519 certificates do not carry a digest in the signature,
        # so tls-server-end-point must use SHA-256, just like libpq.
        name = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, 'localhost')])
        key = ed25519.Ed25519PrivateKey.generate()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(private_key=key, algorithm=None))
        der = cert.public_bytes(serialization.Encoding.DER)
        self.assertEqual(
            _read_x509_signature_algorithm_oid(der), '1.3.101.112')
        self.assertEqual(
            _build_tls_server_end_point_binding(der),
            hashlib.sha256(der).digest())

    def test_malformed_certificates_are_rejected(self):
        for bad in (b'', b'\x31\x02\x01\x02', b'\x30\x03\x02\x01\x01'):
            with self.assertRaises(ValueError):
                _read_x509_signature_algorithm_oid(bad)


class TestChannelBindingParameters(unittest.TestCase):
    """Policy parsing and validation happens before any network I/O."""

    def _parse(self, **kwargs):
        parsed = dict(
            dsn=None, host='localhost', port=None, user='user',
            password='pw', passfile=None, database='db',
            command_timeout=None, statement_cache_size=0,
            max_cached_statement_lifetime=0,
            max_cacheable_statement_size=0, ssl=False,
            direct_tls=None, server_settings=None,
            target_session_attrs=None, krbsrvname=None, gsslib=None,
            service=None, servicefile=None)
        parsed.update(kwargs)
        _, params, _ = connect_utils._parse_connect_arguments(**parsed)
        return params

    def test_default_policy_is_disable(self):
        params = self._parse()
        self.assertEqual(params.channel_binding, ChannelBinding.disable)
        self.assertEqual(params.channel_binding, 'disable')

    def test_policy_string_values(self):
        for value in ('disable', 'prefer', 'require'):
            params = self._parse(channel_binding=value)
            self.assertEqual(params.channel_binding, value)

    def test_policy_enum_value(self):
        params = self._parse(
            channel_binding=ChannelBinding.require)
        self.assertIs(
            params.channel_binding, ChannelBinding.require)

    def test_invalid_policy_raises(self):
        with self.assertRaisesRegex(
            exceptions.ClientConfigurationError,
                '`channel_binding` parameter must be one of'):
            self._parse(channel_binding='bogus')

    def test_invalid_policy_type_raises(self):
        with self.assertRaises(exceptions.ClientConfigurationError):
            self._parse(channel_binding=1)


class TestSCRAMChannelBindingProtocol(unittest.IsolatedAsyncioTestCase):
    """End-to-end protocol behavior against the in-process mock."""

    async def asyncSetUp(self):
        self.tls_server = FakePostgresServer(use_tls=True)
        await self.tls_server.start()
        self.plain_server = FakePostgresServer(use_tls=False)
        await self.plain_server.start()
        self.tls_plainonly_server = FakePostgresServer(
            use_tls=True, mechanisms=(SCRAM_SHA_256,))
        await self.tls_plainonly_server.start()
        self.plain_plusonly_server = FakePostgresServer(
            use_tls=False, mechanisms=(SCRAM_SHA_256_PLUS,))
        await self.plain_plusonly_server.start()
        self.tls_md5_server = FakePostgresServer(
            use_tls=True, auth='md5')
        await self.tls_md5_server.start()
        self.tls_cleartext_server = FakePostgresServer(
            use_tls=True, auth='cleartext')
        await self.tls_cleartext_server.start()
        self.plain_md5_server = FakePostgresServer(
            use_tls=False, auth='md5')
        await self.plain_md5_server.start()
        self.plain_cleartext_server = FakePostgresServer(
            use_tls=False, auth='cleartext')
        await self.plain_cleartext_server.start()
        # Server that upgrades to TLS through the SSLRequest exchange
        # (the non-direct-TLS code path).
        self.tls_upgrade_server = FakePostgresServer(
            use_tls=False, mechanisms=DEFAULT_MECHANISMS)
        await self.tls_upgrade_server.start(ssl_upgrade=True)

    async def asyncTearDown(self):
        for server in (
            self.tls_server, self.plain_server,
            self.tls_plainonly_server, self.plain_plusonly_server,
            self.tls_md5_server, self.tls_cleartext_server,
            self.plain_md5_server, self.plain_cleartext_server,
            self.tls_upgrade_server,
        ):
            await server.close()

    async def _connect(self, server, *, channel_binding=None):
        kwargs = dict(
            host='127.0.0.1', port=server.port, user=USER,
            password=PASSWORD, timeout=5)
        if server.use_tls:
            kwargs['ssl'] = _client_ssl_context()
            kwargs['direct_tls'] = True
        else:
            kwargs['ssl'] = False
        if channel_binding is not None:
            kwargs['channel_binding'] = channel_binding
        return await asyncpg.connect(**kwargs)

    def _last_event(self, server):
        return server.events[-1]

    async def test_default_policy_plain_connection(self):
        con = await self._connect(self.plain_server)
        try:
            event = self._last_event(self.plain_server)
            self.assertEqual(event['mechanism'], SCRAM_SHA_256)
            self.assertTrue(event['initial'].startswith(b'n,,'))
            self.assertTrue(event['verified'])
        finally:
            await con.close()

    async def test_disable_over_tls_picks_plain_with_n_flag(self):
        con = await self._connect(
            self.tls_server, channel_binding='disable')
        try:
            event = self._last_event(self.tls_server)
            self.assertEqual(event['mechanism'], SCRAM_SHA_256)
            self.assertTrue(event['initial'].startswith(b'n,,'))
            self.assertTrue(event['verified'])
        finally:
            await con.close()

    async def test_prefer_over_tls_picks_plus(self):
        con = await self._connect(
            self.tls_server, channel_binding='prefer')
        try:
            event = self._last_event(self.tls_server)
            self.assertEqual(event['mechanism'], SCRAM_SHA_256_PLUS)
            self.assertTrue(
                event['initial'].startswith(
                    b'p=tls-server-end-point,,'))
            self.assertTrue(event['verified'])
        finally:
            await con.close()

    async def test_require_over_tls_picks_plus(self):
        con = await self._connect(
            self.tls_server, channel_binding='require')
        try:
            event = self._last_event(self.tls_server)
            self.assertEqual(event['mechanism'], SCRAM_SHA_256_PLUS)
            self.assertTrue(event['verified'])
        finally:
            await con.close()

    async def test_prefer_over_ssl_request_upgrade_picks_plus(self):
        # ssl='require' negotiates TLS with an SSLRequest followed by
        # start_tls (rather than a direct TLS connection).
        con = await asyncpg.connect(
            host='127.0.0.1', port=self.tls_upgrade_server.port,
            user=USER, password=PASSWORD, ssl='require',
            channel_binding='prefer', timeout=5)
        try:
            self.assertTrue(con._protocol.is_ssl)
            event = self._last_event(self.tls_upgrade_server)
            self.assertEqual(event['tls'], True)
            self.assertEqual(event['mechanism'], SCRAM_SHA_256_PLUS)
            self.assertTrue(
                event['initial'].startswith(
                    b'p=tls-server-end-point,,'))
            self.assertTrue(event['verified'])
        finally:
            await con.close()

    async def test_prefer_over_tls_plain_only_uses_y_flag(self):
        con = await self._connect(
            self.tls_plainonly_server, channel_binding='prefer')
        try:
            event = self._last_event(self.tls_plainonly_server)
            self.assertEqual(event['mechanism'], SCRAM_SHA_256)
            self.assertTrue(event['initial'].startswith(b'y,,'))
            self.assertTrue(event['verified'])
        finally:
            await con.close()

    async def test_prefer_without_tls_falls_back_with_n_flag(self):
        con = await self._connect(
            self.plain_server, channel_binding='prefer')
        try:
            event = self._last_event(self.plain_server)
            self.assertEqual(event['mechanism'], SCRAM_SHA_256)
            self.assertTrue(event['initial'].startswith(b'n,,'))
            self.assertTrue(event['verified'])
        finally:
            await con.close()

    async def test_require_without_tls_fails_before_password(self):
        message = (
            'channel binding is required, but the connection is not '
            'encrypted')
        with self.assertRaisesRegex(exceptions.InterfaceError, message):
            await self._connect(
                self.plain_server, channel_binding='require')
        # No SCRAM response must have been sent.
        event = self._last_event(self.plain_server)
        self.assertNotIn('initial', event)

    async def test_require_over_tls_without_plus_fails(self):
        message = (
            'channel binding is required, but the server did not offer '
            'an authentication mechanism that supports channel binding')
        with self.assertRaisesRegex(exceptions.InterfaceError, message):
            await self._connect(
                self.tls_plainonly_server, channel_binding='require')
        event = self._last_event(self.tls_plainonly_server)
        self.assertNotIn('initial', event)

    async def test_disable_with_only_plus_over_plaintext_fails(self):
        with self.assertRaisesRegex(
                exceptions.InterfaceError,
                'not encrypted with SSL/TLS'):
            await self._connect(
                self.plain_plusonly_server, channel_binding='disable')

    async def test_prefer_with_only_plus_over_plaintext_fails(self):
        with self.assertRaisesRegex(
                exceptions.InterfaceError,
                'not encrypted with SSL/TLS'):
            await self._connect(
                self.plain_plusonly_server, channel_binding='prefer')

    async def test_require_over_tls_rejects_md5(self):
        with self.assertRaisesRegex(
                exceptions.InterfaceError,
                'requested MD5 password authentication'):
            await self._connect(
                self.tls_md5_server, channel_binding='require')
        event = self._last_event(self.tls_md5_server)
        self.assertNotIn('password_response', event)

    async def test_require_over_tls_rejects_cleartext(self):
        with self.assertRaisesRegex(
                exceptions.InterfaceError,
                'requested cleartext password authentication'):
            await self._connect(
                self.tls_cleartext_server, channel_binding='require')
        event = self._last_event(self.tls_cleartext_server)
        self.assertNotIn('password_response', event)

    async def test_md5_authentication_regression(self):
        con = await self._connect(self.plain_md5_server)
        try:
            event = self._last_event(self.plain_md5_server)
            md5_1 = hashlib.md5(
                (PASSWORD + USER).encode('utf-8')).hexdigest()
            md5_2 = hashlib.md5(
                md5_1.encode('ascii') + MD5_SALT).hexdigest()
            self.assertEqual(
                event['password_response'],
                b'md5' + md5_2.encode('ascii') + b'\x00')
        finally:
            await con.close()

    async def test_cleartext_authentication_regression(self):
        con = await self._connect(self.plain_cleartext_server)
        try:
            event = self._last_event(self.plain_cleartext_server)
            self.assertEqual(
                event['password_response'],
                PASSWORD.encode('utf-8') + b'\x00')
        finally:
            await con.close()

    async def test_invalid_policy_makes_no_connection(self):
        before = self.plain_server.connections
        with self.assertRaises(exceptions.ClientConfigurationError):
            await self._connect(
                self.plain_server, channel_binding='bogus')
        # Let the event loop settle and assert no TCP connection
        # was accepted.
        await asyncio.sleep(0.05)
        self.assertEqual(
            self.plain_server.connections, before)

    async def test_pool_uses_policy_for_new_connections(self):
        pool = await asyncpg.create_pool(
            host='127.0.0.1', port=self.tls_server.port, user=USER,
            password=PASSWORD, ssl=_client_ssl_context(),
            direct_tls=True, channel_binding='require',
            min_size=0, max_size=2)
        try:
            con = await pool.acquire()
            try:
                event = self._last_event(self.tls_server)
                self.assertEqual(
                    event['mechanism'], SCRAM_SHA_256_PLUS)
                self.assertTrue(event['verified'])
            finally:
                await pool.release(con)
        finally:
            await pool.close()

    async def test_mid_negotiation_disconnect_does_not_poison(self):
        drop_server = FakePostgresServer(
            use_tls=False, drop_after_initial=True)
        await drop_server.start()
        try:
            with self.assertRaises(Exception):
                await self._connect(drop_server)
        finally:
            await drop_server.close()
        # A subsequent healthy connection must still succeed.
        con = await self._connect(self.plain_server)
        try:
            self.assertTrue(
                self._last_event(self.plain_server)['verified'])
        finally:
            await con.close()
