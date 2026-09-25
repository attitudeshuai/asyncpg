# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import asyncio

import asyncpg

from asyncpg import _testbase as tb


SL = asyncpg.SizeLimits
ERR_SYNTAX = '## definitely not valid SQL ##'


class TestSizeLimitsValidation(tb.TestCase):

    def test_defaults_are_unlimited(self):
        self.assertEqual(
            SL(),
            SL(None, None, None, None),
        )

    def test_valid_values(self):
        limits = SL(0, 1, 2, 2 ** 31 - 1)
        self.assertEqual(limits.query_max_length, 0)
        self.assertEqual(limits.message_max_length, 2 ** 31 - 1)
        replaced = limits.replace(query_max_length=42)
        self.assertEqual(replaced.query_max_length, 42)
        # replace() does not mutate the original.
        self.assertEqual(limits.query_max_length, 0)

    def test_negative_values(self):
        for kwargs in (
            dict(query_max_length=-1),
            dict(parameter_max_length=-1),
            dict(row_max_length=-1),
            dict(message_max_length=-1),
        ):
            with self.assertRaises(ValueError):
                SL(**kwargs)

    def test_wrong_types(self):
        for kwargs in (
            dict(query_max_length=1.5),
            dict(parameter_max_length='1'),
            dict(row_max_length=True),
            dict(message_max_length=False),
        ):
            with self.assertRaises((TypeError, ValueError)):
                SL(**kwargs)

    def test_value_above_protocol_cap(self):
        # The protocol length fields are 32-bit; larger limits are
        # a conflicting configuration.
        with self.assertRaises(ValueError):
            SL(query_max_length=2 ** 31)

    def test_replace_unknown_field(self):
        with self.assertRaises(TypeError):
            SL().replace(unknown=1)

    def test_invalid_connect_arguments(self):
        # Misconfiguration must fail before any connection attempt.
        for kwargs in (
            dict(query_max_length=-1),
            dict(parameter_max_length=1.2),
            dict(row_max_length='10'),
            dict(message_max_length=True),
            dict(message_max_length=2 ** 32),
        ):
            coro = asyncpg.connect(
                host='127.0.0.1', port=1, database='nonexistent',
                timeout=1, **kwargs)
            with self.assertRaises((ValueError, TypeError)):
                self.loop.run_until_complete(coro)

    def test_invalid_pool_arguments(self):
        async def go():
            pool = await asyncpg.create_pool(
                host='127.0.0.1', port=1, database='nonexistent',
                min_size=1, max_size=1, query_max_length=-1)
            await pool.close()

        with self.assertRaises(ValueError):
            self.loop.run_until_complete(go())


class TestSizeLimitsConnected(tb.ConnectedTestCase):

    async def test_default_configuration_is_unlimited(self):
        self.assertEqual(self.con.get_size_limits(), SL())
        self.assertEqual(
            await self.con.fetchval('SELECT $1::int', 42), 42)

    async def test_query_text_limit_simple(self):
        query = ERR_SYNTAX + 'x' * 100
        # If the text were sent, the server would complain about the
        # syntax; the client-side limit must trigger instead.
        with self.assertRaises(asyncpg.QueryTextSizeLimitError) as cm:
            await self.con.execute(
                query, size_limits=SL(query_max_length=32))
        self.assertGreater(cm.exception.size, cm.exception.limit)
        self.assertEqual(cm.exception.limit, 32)
        # Nothing was sent and the connection is still usable.
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)

    async def test_query_text_limit_connection_default(self):
        con = await self.connect(query_max_length=32)
        try:
            with self.assertRaises(asyncpg.QueryTextSizeLimitError):
                await con.execute(ERR_SYNTAX + 'x' * 100)
            self.assertFalse(con.is_closed())
            self.assertEqual(await con.fetchval('SELECT 2'), 2)
        finally:
            await con.close()

    async def test_query_text_limit_on_prepare(self):
        with self.assertRaises(asyncpg.QueryTextSizeLimitError):
            await self.con.prepare(
                'SELECT 1' + 'x' * 200,
                size_limits=SL(query_max_length=32))
        # The statement was never prepared.
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)

    async def test_query_text_limit_uses_encoded_bytes(self):
        # 20 non-ASCII characters encode to 40 UTF-8 bytes.
        query = 'SELECT ' + repr('é' * 20)
        with self.assertRaises(asyncpg.QueryTextSizeLimitError) as cm:
            await self.con.execute(
                query, size_limits=SL(query_max_length=30))
        self.assertGreaterEqual(cm.exception.size, 40)

    async def test_outgoing_message_limit_bind(self):
        # One 200-byte parameter under no per-parameter cap, but the
        # assembled Bind message exceeds the generic message limit.
        with self.assertRaises(asyncpg.MessageSizeLimitError) as cm:
            await self.con.fetchval(
                'SELECT length($1::bytea)', b'x' * 200,
                size_limits=SL(message_max_length=100))
        self.assertGreater(cm.exception.size, cm.exception.limit)
        # Nothing was sent and the connection is reusable.
        self.assertFalse(self.con.is_closed())
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)

    async def test_outgoing_message_limit_parse(self):
        with self.assertRaises(asyncpg.MessageSizeLimitError):
            await self.con.prepare(
                'SELECT 1' + 'y' * 500,
                size_limits=SL(message_max_length=100))
        self.assertFalse(self.con.is_closed())
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)

    async def test_outgoing_message_limit_simple_query(self):
        with self.assertRaises(asyncpg.MessageSizeLimitError):
            await self.con.execute(
                'SELECT ' + '1' * 500,
                size_limits=SL(message_max_length=100))
        self.assertFalse(self.con.is_closed())
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)

    async def test_outgoing_message_limit_executemany(self):
        await self.con.execute('CREATE TEMP TABLE slm (a bytea)')
        with self.assertRaises(asyncpg.MessageSizeLimitError):
            await self.con.executemany(
                'INSERT INTO slm (a) VALUES ($1)',
                [(b'x' * 200,)],
                size_limits=SL(message_max_length=100))
        self.assertFalse(self.con.is_closed())
        self.assertEqual(
            await self.con.fetchval('SELECT count(*) FROM slm'), 0)

    async def test_parameter_limit(self):
        await self.con.execute('CREATE TEMP TABLE slp (a bytea)')
        with self.assertRaises(asyncpg.ParameterSizeLimitError) as cm:
            await self.con.execute(
                'INSERT INTO slp (a) VALUES ($1)', b'x' * 100,
                size_limits=SL(parameter_max_length=32))
        self.assertEqual(cm.exception.size, 100)
        self.assertEqual(cm.exception.limit, 32)
        self.assertIn('$1', str(cm.exception))
        # The bind was never sent and the connection is reusable.
        self.assertEqual(await self.con.fetchval('SELECT count(*) FROM slp'),
                         0)
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)

    async def test_parameter_limit_identifies_argument(self):
        with self.assertRaisesRegex(asyncpg.ParameterSizeLimitError,
                                    r'\$2'):
            await self.con.fetchval(
                'SELECT $1::text || $2::text', 'a', 'x' * 10,
                size_limits=SL(parameter_max_length=4))

    async def test_parameter_limit_allows_null(self):
        # NULL parameters carry no payload and must pass regardless.
        self.assertEqual(
            await self.con.fetchval(
                'SELECT $1::int IS NULL', None,
                size_limits=SL(parameter_max_length=1)),
            True)

    async def test_parameter_limit_connection_default(self):
        con = await self.connect(parameter_max_length=4)
        try:
            with self.assertRaises(asyncpg.ParameterSizeLimitError):
                await con.fetchval('SELECT length($1::bytea)', b'12345')
            self.assertFalse(con.is_closed())
            self.assertEqual(
                await con.fetchval('SELECT length($1::bytea)', b'12'),
                2)
        finally:
            await con.close()

    async def test_per_call_override_does_not_persist(self):
        con = await self.connect(query_max_length=16)
        try:
            # A loose per-call override allows the long query once.
            self.assertEqual(
                await con.fetchval(
                    'SELECT 12345678901234567890',
                    size_limits=SL()),
                12345678901234567890)
            # The connection default is back in force afterwards.
            with self.assertRaises(asyncpg.QueryTextSizeLimitError):
                await con.fetchval('SELECT 12345678901234567890')
        finally:
            await con.close()

    async def test_per_call_override_type_check(self):
        with self.assertRaises(asyncpg.InterfaceError):
            await self.con.fetchval('SELECT 1', size_limits=object())

    async def test_cached_statement_still_checked(self):
        query = 'SELECT $1::int + 1'
        # Prime the statement cache.
        self.assertEqual(await self.con.fetchval(query, 1), 2)
        # The limit must apply even though the statement is cached and
        # its text is not re-sent.
        with self.assertRaises(asyncpg.QueryTextSizeLimitError):
            await self.con.fetchval(
                query, 2, size_limits=SL(query_max_length=8))

    async def test_executemany_element_index_and_atomicity(self):
        await self.con.execute('CREATE TEMP TABLE sle (a bytea)')
        items = [(b'1',), (b'22',), (b'too-big',), (b'9999999',)]
        with self.assertRaisesRegex(asyncpg.ParameterSizeLimitError,
                                    r'element #2'):
            await self.con.executemany(
                'INSERT INTO sle (a) VALUES ($1)', items,
                size_limits=SL(parameter_max_length=3))
        # The implicit transaction must have been rolled back.
        self.assertEqual(
            await self.con.fetchval('SELECT count(*) FROM sle'), 0)
        # Connection remains usable.
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)

    async def test_executemany_first_element_failure(self):
        await self.con.execute('CREATE TEMP TABLE sle0 (a bytea)')
        with self.assertRaises(asyncpg.ParameterSizeLimitError):
            await self.con.executemany(
                'INSERT INTO sle0 (a) VALUES ($1)',
                [(b'too-big',)],
                size_limits=SL(parameter_max_length=3))
        self.assertEqual(
            await self.con.fetchval('SELECT count(*) FROM sle0'), 0)
        self.assertFalse(self.con.is_closed())

    async def test_row_limit(self):
        with self.assertRaises(asyncpg.ResultRowSizeLimitError) as cm:
            await self.con.fetchval(
                "SELECT repeat('x', 100)",
                size_limits=SL(row_max_length=32))
        self.assertGreater(cm.exception.size, cm.exception.limit)
        # Fully-buffered violation: the query is discarded till sync
        # and the connection stays usable.
        self.assertFalse(self.con.is_closed())
        self.assertEqual(
            await self.con.fetchval('SELECT 1',
                                    size_limits=SL(row_max_length=32)),
            1)

    async def test_row_limit_connection_default(self):
        con = await self.connect(row_max_length=32)
        try:
            with self.assertRaises(asyncpg.ResultRowSizeLimitError):
                await con.fetchval("SELECT repeat('x', 100)")
            self.assertFalse(con.is_closed())
            self.assertEqual(await con.fetchval('SELECT 1'), 1)
        finally:
            await con.close()

    async def test_row_limit_check_precedes_message_limit(self):
        # The result row (~106 bytes payload / ~111 bytes wire) violates
        # both limits; the message limit (100) is above the metadata
        # messages, and the specific row limit (80) must be reported.
        with self.assertRaises(asyncpg.ResultRowSizeLimitError):
            await self.con.fetchval(
                "SELECT repeat('x', 100)",
                size_limits=SL(row_max_length=80, message_max_length=100))

    async def test_message_limit_applies_to_row_without_row_limit(self):
        # Same row, only the generic message limit configured.
        with self.assertRaises(asyncpg.MessageSizeLimitError):
            await self.con.fetchval(
                "SELECT repeat('x', 100)",
                size_limits=SL(message_max_length=100))

    async def test_message_limit_small_oversize_is_recoverable(self):
        # A tiny oversize message arrives fully buffered, so the
        # connection can discard the query and stay usable.
        with self.assertRaises(asyncpg.MessageSizeLimitError):
            await self.con.fetchval(
                "SELECT repeat('x', 100)",
                size_limits=SL(message_max_length=32))
        self.assertFalse(self.con.is_closed())
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)

    async def test_message_limit_early_header_aborts_connection(self):
        # A multi-megabyte message cannot be fully buffered by the
        # time its header arrives; the connection is terminated with a
        # clear client error.
        con = await self.connect(message_max_length=1024)
        try:
            with self.assertRaises(asyncpg.MessageSizeLimitError) as cm:
                await con.fetchval("SELECT repeat('y', 5_000_000)")
            self.assertGreater(cm.exception.size, cm.exception.limit)
            self.assertTrue(con.is_closed())
        finally:
            await con.close()

    async def test_notifications_exempt_from_message_limit(self):
        got = self.loop.create_future()

        def listener(connection, pid, channel, payload):
            got.set_result(payload)

        con = await self.connect(message_max_length=64)
        try:
            await con.add_listener('sl_chan', listener)
            await con.execute("NOTIFY sl_chan, 'hello'")
            payload = await asyncio.wait_for(got, 10)
            self.assertEqual(payload, 'hello')
        finally:
            await con.close()

    async def test_independent_connections(self):
        limited = await self.connect(query_max_length=16)
        try:
            with self.assertRaises(asyncpg.QueryTextSizeLimitError):
                await limited.fetchval('SELECT 12345678901234567890')
            # The other connection is unaffected.
            self.assertEqual(
                await self.con.fetchval('SELECT 12345678901234567890'),
                12345678901234567890)
        finally:
            await limited.close()

    async def test_prepared_statement_methods(self):
        await self.con.execute('CREATE TEMP TABLE slps (a bytea)')
        stmt = await self.con.prepare('INSERT INTO slps (a) VALUES ($1)')
        with self.assertRaises(asyncpg.ParameterSizeLimitError):
            await stmt.fetch(b'x' * 100,
                             size_limits=SL(parameter_max_length=4))
        self.assertEqual(
            await self.con.fetchval('SELECT count(*) FROM slps'), 0)

        stmt2 = await self.con.prepare('SELECT length($1::bytea)')
        self.assertEqual(
            await stmt2.fetchval(b'1234567890',
                                 size_limits=SL(parameter_max_length=64)),
            10)

    async def test_cursor_factory_with_limits(self):
        async with self.con.transaction():
            cur = self.con.cursor(
                'SELECT i FROM generate_series(0, 4) AS i',
                size_limits=SL(row_max_length=1024))
            values = [row['i'] async for row in cur]
        self.assertEqual(values, [0, 1, 2, 3, 4])

    async def test_cursor_row_limit_violation(self):
        async with self.con.transaction():
            cur = self.con.cursor(
                "SELECT repeat('x', 100)",
                size_limits=SL(row_max_length=32))
            portal = await cur
            with self.assertRaises(asyncpg.ResultRowSizeLimitError):
                await portal.fetch(1)
        self.assertFalse(self.con.is_closed())


class TestSizeLimitsCopy(tb.ConnectedTestCase):

    async def test_copy_in_statement_query_limit(self):
        await self.con.execute('CREATE TEMP TABLE slc1 (a text)')
        with self.assertRaises(asyncpg.QueryTextSizeLimitError):
            await self.con.copy_to_table(
                'slc1', source=bytearray(b'x\n'),
                size_limits=SL(query_max_length=8))
        self.assertEqual(
            await self.con.fetchval('SELECT count(*) FROM slc1'), 0)

    async def test_copy_in_data_message_limit(self):
        await self.con.execute('CREATE TEMP TABLE slc2 (a text)')
        with self.assertRaises(asyncpg.MessageSizeLimitError) as cm:
            await self.con.copy_to_table(
                'slc2', source=bytearray(b'x' * 128),
                size_limits=SL(message_max_length=64))
        self.assertEqual(cm.exception.size, 133)
        # CopyFail is sent deterministically, the connection survives.
        self.assertFalse(self.con.is_closed())
        self.assertEqual(
            await self.con.fetchval('SELECT count(*) FROM slc2'), 0)
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)

    async def test_copy_records_message_limit(self):
        await self.con.execute('CREATE TEMP TABLE slc3 (a bytea)')
        with self.assertRaises(asyncpg.MessageSizeLimitError):
            await self.con.copy_records_to_table(
                'slc3', records=[(b'x' * 4096,)],
                size_limits=SL(message_max_length=1024))
        self.assertFalse(self.con.is_closed())
        self.assertEqual(
            await self.con.fetchval('SELECT count(*) FROM slc3'), 0)

    async def test_copy_out_message_limit(self):
        await self.con.execute('CREATE TEMP TABLE slc4 (a text)')
        await self.con.execute(
            "INSERT INTO slc4 (a) VALUES (repeat('z', 200))")
        chunks = []

        async def sink(data):
            chunks.append(data)

        with self.assertRaises(asyncpg.MessageSizeLimitError):
            await self.con.copy_from_table(
                'slc4', output=sink,
                size_limits=SL(message_max_length=64))
        self.assertFalse(self.con.is_closed())
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)

    async def test_copy_from_query_mogrified_argument(self):
        with self.assertRaises(asyncpg.QueryTextSizeLimitError):
            async def sink(data):
                pass

            await self.con.copy_from_query(
                'SELECT $1::bytea', b'x' * 256, output=sink,
                size_limits=SL(query_max_length=64))
        self.assertEqual(await self.con.fetchval('SELECT 1'), 1)


class TestSizeLimitsPool(tb.ClusterTestCase):

    async def test_pool_limits_apply_to_connections(self):
        pool = await self.create_pool(
            min_size=1, max_size=1,
            query_max_length=16)
        async with pool.acquire() as con:
            with self.assertRaises(asyncpg.QueryTextSizeLimitError):
                await con.fetchval('SELECT 12345678901234567890')

    async def test_pool_per_call_override_isolated(self):
        pool = await self.create_pool(
            min_size=1, max_size=1,
            query_max_length=16)
        async with pool.acquire() as con:
            self.assertEqual(
                await con.fetchval(
                    'SELECT 12345678901234567890', size_limits=SL()),
                12345678901234567890)
        async with pool.acquire() as con:
            # The temporary override must not survive release/reuse.
            with self.assertRaises(asyncpg.QueryTextSizeLimitError):
                await con.fetchval('SELECT 12345678901234567890')

    async def test_pool_row_limit(self):
        pool = await self.create_pool(
            min_size=1, max_size=1,
            row_max_length=32)
        async with pool.acquire() as con:
            with self.assertRaises(asyncpg.ResultRowSizeLimitError):
                await con.fetchval("SELECT repeat('x', 100)")
            self.assertFalse(con.is_closed())
