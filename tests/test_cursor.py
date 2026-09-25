# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import asyncio
import warnings

import asyncpg
import inspect

from asyncpg import _testbase as tb


class TestIterableCursor(tb.ConnectedTestCase):

    async def test_cursor_iterable_01(self):
        st = await self.con.prepare('SELECT generate_series(0, 20)')
        expected = await st.fetch()

        for prefetch in range(1, 25):
            with self.subTest(prefetch=prefetch):
                async with self.con.transaction():
                    result = []
                    async for rec in st.cursor(prefetch=prefetch):
                        result.append(rec)

                self.assertEqual(
                    result, expected,
                    'result != expected for prefetch={}'.format(prefetch))

    async def test_cursor_iterable_02(self):
        # Test that it's not possible to create a cursor without hold
        # outside of a transaction
        s = await self.con.prepare(
            'DECLARE t BINARY CURSOR WITHOUT HOLD FOR SELECT 1')
        with self.assertRaises(asyncpg.NoActiveSQLTransactionError):
            await s.fetch()

        # Now test that statement.cursor() does not let you
        # iterate over it outside of a transaction
        st = await self.con.prepare('SELECT generate_series(0, 20)')

        it = st.cursor(prefetch=5).__aiter__()
        if inspect.isawaitable(it):
            it = await it

        with self.assertRaisesRegex(asyncpg.NoActiveSQLTransactionError,
                                    'cursor cannot be created.*transaction'):
            await it.__anext__()

    async def test_cursor_iterable_03(self):
        st = await self.con.prepare('SELECT generate_series(0, 20)')

        it = st.cursor().__aiter__()
        if inspect.isawaitable(it):
            it = await it

        st._state.mark_closed()

        with self.assertRaisesRegex(asyncpg.InterfaceError,
                                    'statement is closed'):
            async for _ in it:  # NOQA
                pass

    async def test_cursor_iterable_04(self):
        st = await self.con.prepare('SELECT generate_series(0, 20)')
        st._state.mark_closed()

        with self.assertRaisesRegex(asyncpg.InterfaceError,
                                    'statement is closed'):
            async for _ in st.cursor():  # NOQA
                pass

    async def test_cursor_iterable_05(self):
        st = await self.con.prepare('SELECT generate_series(0, 20)')
        for prefetch in range(-1, 1):
            with self.subTest(prefetch=prefetch):
                with self.assertRaisesRegex(asyncpg.InterfaceError,
                                            'must be greater than zero'):
                    async for _ in st.cursor(prefetch=prefetch):  # NOQA
                        pass

    async def test_cursor_iterable_06(self):
        recs = []

        async with self.con.transaction():
            await self.con.execute('''
                CREATE TABLE cursor_iterable_06 (id int);
                INSERT INTO cursor_iterable_06 VALUES (0), (1);
            ''')
            try:
                cur = self.con.cursor('SELECT * FROM cursor_iterable_06')
                async for rec in cur:
                    recs.append(rec)
            finally:
                # Check that after iteration has exhausted the cursor,
                # its associated portal is closed properly, unlocking
                # the table.
                await self.con.execute('DROP TABLE cursor_iterable_06')

        self.assertEqual(recs, [(i,) for i in range(2)])

    async def test_cursor_iterable_07_explicit_close(self):
        async with self.con.transaction():
            it = self.con.cursor(
                'SELECT generate_series(0, 20)', prefetch=2).__aiter__()
            self.assertEqual(await it.__anext__(), (0,))
            self.assertFalse(it.closed)

            await it.close()
            self.assertTrue(it.closed)
            self.assertIsNone(it._portal_name)

            # close() is idempotent and never touches the server.
            await it.close()

            # Fetching after an explicit close fails client-side.
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'cursor is closed'):
                await it.__anext__()

    async def test_cursor_iterable_08_close_before_iteration(self):
        async with self.con.transaction():
            # Closing an iterator that was never started sends nothing
            # and marks the handle closed.
            it = self.con.cursor(
                'SELECT generate_series(0, 20)', prefetch=2).__aiter__()
            self.assertIsNone(it._state)
            self.assertIsNone(it._portal_name)
            await it.close()
            self.assertTrue(it.closed)
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'cursor is closed'):
                await it.__anext__()

    async def test_cursor_iterable_09_factory_context_manager(self):
        async with self.con.transaction():
            async with self.con.cursor(
                    'SELECT generate_series(0, 20)', prefetch=5) as it:
                self.assertFalse(it.closed)
                got = []
                async for rec in it:
                    got.append(rec)
                    if rec[0] == 7:
                        break

            # The portal is closed deterministically on context exit,
            # even though the iteration was not exhausted.
            self.assertTrue(it.closed)
            self.assertIsNone(it._portal_name)
            self.assertEqual(got, [(i,) for i in range(8)])

            # The table can now be modified even though the portal was
            # abandoned mid-iteration.
            await self.con.execute('SELECT 1')

    async def test_cursor_iterable_10_factory_context_manager_exc(self):
        class BoomError(Exception):
            pass

        async with self.con.transaction():
            with self.assertRaises(BoomError):
                async with self.con.cursor(
                        'SELECT generate_series(0, 20)', prefetch=5) as it:
                    async for rec in it:
                        if rec[0] == 3:
                            raise BoomError
            self.assertTrue(it.closed)
            self.assertIsNone(it._portal_name)

    async def test_cursor_iterable_11_iterator_context_manager(self):
        async with self.con.transaction():
            it = self.con.cursor(
                'SELECT generate_series(0, 20)', prefetch=5).__aiter__()
            async with it:
                self.assertEqual(await it.__anext__(), (0,))
            self.assertTrue(it.closed)
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'cursor is closed'):
                await it.__anext__()

    async def test_cursor_iterable_12_close_during_fetch(self):
        async with self.con.transaction():
            it = self.con.cursor(
                'SELECT i, pg_sleep(0.02) '
                'FROM generate_series(0, 20) i',
                prefetch=2).__aiter__()

            fetch = asyncio.ensure_future(it.__anext__())
            # Make sure the fetch has started before closing.
            await asyncio.sleep(0.01)
            close = asyncio.ensure_future(it.close())

            # close() waits for the in-flight fetch; the row being
            # fetched is delivered normally (pg_sleep() returns NULL).
            self.assertEqual(await fetch, (0, None))
            await close
            self.assertTrue(it.closed)

            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'cursor is closed'):
                await it.__anext__()


class TestCursor(tb.ConnectedTestCase):

    async def test_cursor_01(self):
        st = await self.con.prepare('SELECT generate_series(0, 20)')
        with self.assertRaisesRegex(asyncpg.NoActiveSQLTransactionError,
                                    'cursor cannot be created.*transaction'):
            await st.cursor()

    async def test_cursor_02(self):
        st = await self.con.prepare('SELECT generate_series(0, 20)')
        async with self.con.transaction():
            cur = await st.cursor()

            for i in range(-1, 1):
                with self.assertRaisesRegex(asyncpg.InterfaceError,
                                            'greater than zero'):
                    await cur.fetch(i)

            res = await cur.fetch(2)
            self.assertEqual(res, [(0,), (1,)])

            rec = await cur.fetchrow()
            self.assertEqual(rec, (2,))

            r = repr(cur)
            self.assertTrue(r.startswith('<asyncpg.Cursor '))
            self.assertNotIn(' exhausted ', r)
            self.assertIn('"SELECT generate', r)

            moved = await cur.forward(5)
            self.assertEqual(moved, 5)

            rec = await cur.fetchrow()
            self.assertEqual(rec, (8,))

            res = await cur.fetch(100)
            self.assertEqual(res, [(i,) for i in range(9, 21)])

            self.assertIsNone(await cur.fetchrow())
            self.assertEqual(await cur.fetch(5), [])

            r = repr(cur)
            self.assertTrue(r.startswith('<asyncpg.Cursor '))
            self.assertIn(' exhausted ', r)
            self.assertIn('"SELECT generate', r)

    async def test_cursor_03(self):
        st = await self.con.prepare('SELECT generate_series(0, 20)')
        async with self.con.transaction():
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'prefetch argument can only'):
                await st.cursor(prefetch=10)

    async def test_cursor_04(self):
        async with self.con.transaction():
            st = await self.con.cursor('SELECT generate_series(0, 100)')
            await st.forward(42)
            self.assertEqual(await st.fetchrow(), (42,))

    async def test_cursor_06_explicit_close(self):
        st = await self.con.prepare('SELECT generate_series(0, 20)')
        async with self.con.transaction():
            cur = await st.cursor()
            self.assertEqual(await cur.fetch(2), [(0,), (1,)])
            self.assertFalse(cur.closed)
            self.assertIsNotNone(cur._portal_name)

            await cur.close()
            self.assertTrue(cur.closed)
            self.assertIsNone(cur._portal_name)

            # Closing again is a no-op.
            await cur.close()
            self.assertTrue(cur.closed)

            # All data-access methods fail client-side with a clear
            # error, and never send the stale portal name to the server.
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'cursor is closed'):
                await cur.fetch(1)
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'cursor is closed'):
                await cur.fetchrow()
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'cursor is closed'):
                await cur.forward(1)

    async def test_cursor_07_close_after_exhaustion(self):
        async with self.con.transaction():
            cur = await self.con.cursor('SELECT generate_series(0, 1)')
            self.assertEqual(await cur.fetch(100), [(0,), (1,)])
            # Exhaustion itself keeps the existing semantics; an explicit
            # close afterwards is still valid.
            await cur.close()
            self.assertTrue(cur.closed)
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'cursor is closed'):
                await cur.fetch(1)

    async def test_cursor_08_context_manager(self):
        async with self.con.transaction():
            cur = await self.con.cursor('SELECT generate_series(0, 20)')
            async with cur:
                self.assertEqual(await cur.fetchrow(), (0,))
            self.assertTrue(cur.closed)

    async def test_cursor_09_context_manager_exception_propagates(self):
        class BoomError(Exception):
            pass

        async with self.con.transaction():
            cur = await self.con.cursor('SELECT generate_series(0, 20)')
            with self.assertRaises(BoomError):
                async with cur:
                    self.assertEqual(await cur.fetchrow(), (0,))
                    raise BoomError
            self.assertTrue(cur.closed)

    async def test_cursor_10_close_does_not_affect_other_cursors(self):
        async with self.con.transaction():
            a = await self.con.cursor('SELECT generate_series(0, 100)')
            b = await self.con.cursor('SELECT generate_series(0, 100)')
            self.assertEqual(await a.fetchrow(), (0,))
            self.assertEqual(await b.fetchrow(), (0,))
            self.assertEqual(await a.fetch(2), [(1,), (2,)])
            await a.close()
            # b keeps its fetch position and results.
            self.assertEqual(await b.fetch(2), [(1,), (2,)])
            self.assertEqual(await b.forward(2), 2)
            self.assertEqual(await b.fetchrow(), (5,))
            await b.close()

    async def test_cursor_12_close_failure_still_marks_closed(self):
        class BrokenProtocol:
            def __init__(self, proto):
                self._proto = proto

            def __getattr__(self, name):
                return getattr(self._proto, name)

            async def close_portal(self, portal_name, timeout):
                raise asyncpg.PostgresConnectionError(
                    'simulated close failure')

        async with self.con.transaction():
            cur = await self.con.cursor('SELECT generate_series(0, 5)')
            self.assertEqual(await cur.fetchrow(), (0,))
            real_proto = self.con._protocol
            self.con._protocol = BrokenProtocol(real_proto)
            try:
                with self.assertRaises(asyncpg.PostgresConnectionError):
                    await cur.close()
                # Despite the failure the handle is closed and its portal
                # name is forgotten, so no duplicate close can ever happen.
                self.assertTrue(cur.closed)
                self.assertIsNone(cur._portal_name)
                # Repeated close is a no-op and raises nothing.
                await cur.close()
            finally:
                self.con._protocol = real_proto

    async def test_cursor_11_close_releases_server_portal(self):
        # An open portal holds locks; prove that close() releases the
        # portal server-side while still inside the transaction.
        async with self.con.transaction():
            await self.con.execute('CREATE TABLE cursor_close_11 (id int)')
            try:
                cur = await self.con.cursor('SELECT * FROM cursor_close_11')
                await cur.fetchrow()
                await cur.close()
                # Would block/fail if the portal still pinned the table.
                await self.con.execute('DROP TABLE cursor_close_11')
            except BaseException:
                await self.con.execute('DROP TABLE IF EXISTS cursor_close_11')
                raise

    @tb.with_connection_options(statement_cache_size=0)
    async def test_cursor_05_unnamed_statement_reparsed(self):
        await self.con.execute(
            "CREATE TYPE cursor_05_t AS ENUM ('foo', 'bar')"
        )
        try:
            async with self.con.transaction():
                # Enum introspection replaces the unnamed statement on the
                # server, so opening the cursor must re-parse it first.
                st = await self.con.prepare('''
                    SELECT $1::int, $2::int, 'foo'::cursor_05_t
                ''')
                self.assertEqual(st.get_name(), '')

                cur = await st.cursor(1, 2)
                self.assertEqual(await cur.fetch(1), [(1, 2, 'foo')])
        finally:
            await self.con.execute('DROP TYPE cursor_05_t')


class TestCursorTransactionLifecycle(tb.ConnectedTestCase):

    async def test_cursor_txlifecycle_01_commit_invalidates(self):
        async with self.con.transaction():
            cur = await self.con.cursor('SELECT generate_series(0, 20)')
            self.assertEqual(await cur.fetchrow(), (0,))
        self.assertTrue(cur.closed)

        # The stale portal name is never sent to the server; a clear
        # client-side exception is raised instead.
        with self.assertRaisesRegex(asyncpg.InterfaceError,
                                    'cursor is closed.*transaction'):
            await cur.fetchrow()
        with self.assertRaisesRegex(asyncpg.InterfaceError,
                                    'cursor is closed.*transaction'):
            await cur.forward(1)

        # A new transaction does not resurrect the cursor: it has to be
        # re-declared explicitly.
        async with self.con.transaction():
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'cursor is closed'):
                await cur.fetchrow()
            # The connection itself is fully usable with a new cursor.
            new_cur = await self.con.cursor('SELECT 1')
            self.assertEqual(await new_cur.fetchrow(), (1,))
            await new_cur.close()

    async def test_cursor_txlifecycle_02_rollback_invalidates(self):
        tr = self.con.transaction()
        await tr.start()
        cur = await self.con.cursor('SELECT generate_series(0, 20)')
        self.assertEqual(await cur.fetchrow(), (0,))
        await tr.rollback()
        self.assertTrue(cur.closed)
        with self.assertRaisesRegex(asyncpg.InterfaceError,
                                    'cursor is closed.*transaction'):
            await cur.fetchrow()

    async def test_cursor_txlifecycle_03_iterator_invalidated(self):
        async with self.con.transaction():
            it = self.con.cursor(
                'SELECT generate_series(0, 20)', prefetch=5).__aiter__()
            self.assertEqual(await it.__anext__(), (0,))
        self.assertTrue(it.closed)
        with self.assertRaisesRegex(asyncpg.InterfaceError,
                                    'cursor is closed'):
            await it.__anext__()

    async def test_cursor_txlifecycle_04_savepoint_does_not_invalidate(self):
        async with self.con.transaction():
            cur = await self.con.cursor('SELECT generate_series(0, 100)')
            self.assertEqual(await cur.fetchrow(), (0,))
            # A nested savepoint block must leave the portal intact.
            async with self.con.transaction():
                self.assertEqual(await cur.fetchrow(), (1,))
            self.assertFalse(cur.closed)
            self.assertEqual(await cur.fetchrow(), (2,))
            await cur.close()

    async def test_cursor_txlifecycle_05_explicit_close_survives_commit(self):
        # Explicitly closing within the transaction, then committing,
        # must not raise and must leave the handle closed.
        async with self.con.transaction():
            cur = await self.con.cursor('SELECT generate_series(0, 5)')
            self.assertEqual(await cur.fetchrow(), (0,))
            await cur.close()
        self.assertTrue(cur.closed)
        with self.assertRaisesRegex(asyncpg.InterfaceError,
                                    'cursor is closed'):
            await cur.fetchrow()


class TestCursorConnectionLifecycle(tb.ClusterTestCase):

    async def test_cursor_connlifecycle_01_close_invalidates(self):
        con = await self.connect()
        try:
            async with con.transaction():
                cur = await con.cursor('SELECT generate_series(0, 5)')
                self.assertEqual(await cur.fetchrow(), (0,))
            await con.close()
            self.assertTrue(cur.closed)

            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'connection is closed'):
                await cur.fetchrow()
        finally:
            if not con.is_closed():
                await con.close()

    async def test_cursor_connlifecycle_02_terminate_invalidates(self):
        con = await self.connect()
        tr = con.transaction()
        await tr.start()
        cur = await con.cursor('SELECT generate_series(0, 5)')
        self.assertEqual(await cur.fetchrow(), (0,))
        con.terminate()
        self.assertTrue(cur.closed)
        with self.assertRaisesRegex(asyncpg.InterfaceError,
                                    'connection is closed'):
            await cur.fetchrow()


class TestCursorPoolLifecycle(tb.ClusterTestCase):

    async def test_cursor_poollifecycle_01_release_cleans_up(self):
        # Releasing a connection with an open (manually managed)
        # transaction is expected to log via the loop exception handler,
        # as reset() performs the rollback on release.
        async with self.create_pool(database='postgres',
                                    min_size=1, max_size=1) as pool:
            stale = {}
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                with self.assertLoopErrorHandlerCalled(
                        'an active transaction'):
                    async with pool.acquire() as con:
                        tr = con.transaction()
                        await tr.start()
                        cur = await con.cursor('SELECT generate_series(0, 5)')
                        self.assertEqual(await cur.fetchrow(), (0,))
                        stale['cur'] = cur
                    # <- the connection is released here; reset()
                    #    rolls back, closes the portal and invalidates
                    #    the cursor.

            cur = stale['cur']
            self.assertTrue(
                any(issubclass(w.category, asyncpg.InterfaceWarning)
                    and 'cursor' in str(w.message)
                    for w in caught),
                [str(w.message) for w in caught])
            self.assertTrue(cur.closed)

            # The handle is stale now: closing or fetching raises the
            # same client-side error as other resources invalidated by
            # release, and sends no request to the server.
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'released back to the pool'):
                await cur.close()
            with self.assertRaisesRegex(asyncpg.InterfaceError,
                                        'released back to the pool'):
                await cur.fetchrow()

            # The connection itself is healthy when handed out again.
            async with pool.acquire() as con:
                self.assertEqual(await con.fetchval('SELECT 42'), 42)

    async def test_cursor_poollifecycle_02_explicit_close_no_warning(self):
        async with self.create_pool(database='postgres',
                                    min_size=1, max_size=1) as pool:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                async with pool.acquire() as con:
                    async with con.transaction():
                        cur = await con.cursor('SELECT generate_series(0, 5)')
                        self.assertEqual(await cur.fetchrow(), (0,))
                        await cur.close()
                    # transaction committed before release, and the cursor
                    # was closed explicitly: nothing to warn about.

            self.assertFalse(
                any('cursor' in str(w.message) for w in caught),
                [str(w.message) for w in caught])
