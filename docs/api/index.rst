.. _asyncpg-api-reference:

=============
API Reference
=============

.. module:: asyncpg
    :synopsis: A fast PostgreSQL Database Client Library for Python/asyncio

.. currentmodule:: asyncpg


.. _asyncpg-api-connection:

Connection
==========

.. autofunction:: asyncpg.connection.connect


.. autoclass:: asyncpg.connection.Connection
   :members:


.. _asyncpg-api-prepared-stmt:

Prepared Statements
===================

Prepared statements are a PostgreSQL feature that can be used to optimize the
performance of queries that are executed more than once.  When a query
is *prepared* by a call to :meth:`Connection.prepare`, the server parses,
analyzes and compiles the query allowing to reuse that work once there is
a need to run the same query again.

.. code-block:: pycon

   >>> import asyncpg, asyncio
   >>> async def run():
   ...     conn = await asyncpg.connect()
   ...     stmt = await conn.prepare('''SELECT 2 ^ $1''')
   ...     print(await stmt.fetchval(10))
   ...     print(await stmt.fetchval(20))
   ...
   >>> asyncio.run(run())
   1024.0
   1048576.0

.. note::

   asyncpg automatically maintains a small LRU cache for queries executed
   during calls to the :meth:`~Connection.fetch`, :meth:`~Connection.fetchrow`,
   or :meth:`~Connection.fetchval` methods.

.. warning::

   If you are using pgbouncer with ``pool_mode`` set to ``transaction`` or
   ``statement``, prepared statements will not work correctly.  See
   :ref:`asyncpg-prepared-stmt-errors` for more information.


.. autoclass:: asyncpg.prepared_stmt.PreparedStatement()
   :members:


.. _asyncpg-api-transaction:

Transactions
============

The most common way to use transactions is through an ``async with`` statement:

.. code-block:: python

   async with connection.transaction():
       await connection.execute("INSERT INTO mytable VALUES(1, 2, 3)")


asyncpg supports nested transactions (a nested transaction context will create
a `savepoint`_.):

.. code-block:: python

   async with connection.transaction():
       await connection.execute('CREATE TABLE mytab (a int)')

       try:
           # Create a nested transaction:
           async with connection.transaction():
               await connection.execute('INSERT INTO mytab (a) VALUES (1), (2)')
               # This nested transaction will be automatically rolled back:
               raise Exception
       except:
           # Ignore exception
           pass

       # Because the nested transaction was rolled back, there
       # will be nothing in `mytab`.
       assert await connection.fetch('SELECT a FROM mytab') == []

Alternatively, transactions can be used without an ``async with`` block:

.. code-block:: python

    tr = connection.transaction()
    await tr.start()
    try:
        ...
    except:
        await tr.rollback()
        raise
    else:
        await tr.commit()


See also the
:meth:`Connection.transaction() <asyncpg.connection.Connection.transaction>`
function.

.. _savepoint: https://www.postgresql.org/docs/current/static/sql-savepoint.html


.. autoclass:: asyncpg.transaction.Transaction()
   :members:

   .. describe:: async with c:

      start and commit/rollback the transaction or savepoint block
      automatically when entering and exiting the code inside the
      context manager block.


.. _asyncpg-api-cursor:

Cursors
=======

Cursors are useful when there is a need to iterate over the results of
a large query without fetching all rows at once.  The cursor interface
provided by asyncpg supports *asynchronous iteration* via the ``async for``
statement, and also a way to read row chunks and skip forward over the
result set.

To iterate over a cursor using a connection object use
:meth:`Connection.cursor() <asyncpg.connection.Connection.cursor>`.
To make the iteration efficient, the cursor will prefetch records to
reduce the number of queries sent to the server:

.. code-block:: python

    async def iterate(con: Connection):
        async with con.transaction():
            # Postgres requires non-scrollable cursors to be created
            # and used in a transaction.
            async for record in con.cursor('SELECT generate_series(0, 100)'):
                print(record)

Or, alternatively, you can iterate over the cursor manually (cursor
won't be prefetching any rows):

.. code-block:: python

    async def iterate(con: Connection):
        async with con.transaction():
            # Postgres requires non-scrollable cursors to be created
            # and used in a transaction.

            # Create a Cursor object
            cur = await con.cursor('SELECT generate_series(0, 100)')

            # Move the cursor 10 rows forward
            await cur.forward(10)

            # Fetch one row and print it
            print(await cur.fetchrow())

            # Fetch a list of 5 rows and print it
            print(await cur.fetch(5))

It's also possible to create cursors from prepared statements:

.. code-block:: python

    async def iterate(con: Connection):
        # Create a prepared statement that will accept one argument
        stmt = await con.prepare('SELECT generate_series(0, $1)')

        async with con.transaction():
            # Postgres requires non-scrollable cursors to be created
            # and used in a transaction.

            # Execute the prepared statement passing `10` as the
            # argument -- that will generate a series or records
            # from 0..10.  Iterate over all of them and print every
            # record.
            async for record in stmt.cursor(10):
                print(record)


.. note::

   Cursors created by a call to
   :meth:`Connection.cursor() <asyncpg.connection.Connection.cursor>` or
   :meth:`PreparedStatement.cursor() <asyncpg.prepared_stmt.PreparedStatement.cursor>`
   are *non-scrollable*: they can only be read forwards.  To create a scrollable
   cursor, use the ``DECLARE ... SCROLL CURSOR`` SQL statement directly.

.. warning::

   Cursors created by a call to
   :meth:`Connection.cursor() <asyncpg.connection.Connection.cursor>` or
   :meth:`PreparedStatement.cursor() <asyncpg.prepared_stmt.PreparedStatement.cursor>`
   cannot be used outside of a transaction.  Any such attempt will result in
   :exc:`~asyncpg.exceptions.InterfaceError`.

   To create a cursor usable outside of a transaction, use the
   ``DECLARE ... CURSOR WITH HOLD`` SQL statement directly.

Closing cursors
---------------

A cursor holds a server-side resource (a *portal*) that should be released
as soon as the cursor is no longer needed.  Both
:class:`~asyncpg.cursor.Cursor` and the asynchronous iterator returned by
:class:`~asyncpg.cursor.CursorFactory` provide an explicit
:meth:`~asyncpg.cursor.Cursor.close` coroutine and can also be used as
asynchronous context managers::

    async with con.transaction():
        cur = await con.cursor('SELECT generate_series(0, 100)')
        async with cur:
            print(await cur.fetch(10))
        # the portal is released here

    async with con.transaction():
        async with con.cursor('SELECT generate_series(0, 100)') as cur:
            async for row in cur:
                if row[0] == 10:
                    break
        # breaking out of the iteration early leaves the portal open,
        # but exiting the context manager closes it deterministically

The rules are:

* ``close()`` sends the ``Close`` message for the portal immediately and
  marks the cursor as closed, as reported by the
  :attr:`~asyncpg.cursor.Cursor.closed` property.  Any subsequent attempt
  to fetch or skip rows raises
  :exc:`~asyncpg.exceptions.InterfaceError` -- no request for the stale
  portal is ever sent to the server.

* ``close()`` is idempotent.  Closing an already closed cursor (including a
  cursor that was invalidated when its transaction ended) does nothing and
  sends no request.

* Closing a cursor never affects other cursors on the same connection.

* When the top-level transaction is committed or rolled back, all cursors
  opened in it are invalidated client-side, because the server destroys
  their portals.  Fetching from such a cursor (even after starting a new
  transaction) raises
  :exc:`~asyncpg.exceptions.InterfaceError` explaining that the cursor is
  closed; the cursor must be re-declared explicitly.  Releasing or rolling
  back to a *savepoint* does not invalidate cursors.

* When a connection is released back to a pool, asyncpg resets it (which
  rolls back any open transaction and closes the portals) and invalidates
  the stale cursor handles.  Releasing a connection that still has open
  cursors emits an :class:`~asyncpg.exceptions.InterfaceWarning`.
  Closing or otherwise using such a stale handle raises
  :exc:`~asyncpg.exceptions.InterfaceError` and sends no request to the
  server.  Closing or terminating a connection likewise invalidates every
  cursor opened on it.

* If a fetch or a skip on the cursor is in progress in another
  :class:`~asyncio.Task` when ``close()`` is called, ``close()`` waits for
  that operation to finish and only then closes the portal.  Rows already
  returned by the in-progress operation remain delivered to its caller.

* Iterating a cursor to exhaustion closes its portal automatically, as
  before.

.. versionadded:: 0.32.0
   Explicit cursor closing, the ``closed`` property and asynchronous
   context manager support.


.. autoclass:: asyncpg.cursor.CursorFactory()
   :members:

   .. describe:: async for row in c

      Execute the statement and iterate over the results asynchronously.

   .. describe:: await c

      Execute the statement and return an instance of
      :class:`~asyncpg.cursor.Cursor` which can be used to navigate over and
      fetch subsets of the query results.

   .. describe:: async with c as cur

      Open an asynchronous iterator for the results and close it
      deterministically on exit of the context manager block.


.. autoclass:: asyncpg.cursor.Cursor()
   :members:

   .. describe:: async with c

      Close the cursor deterministically on exit of the context manager
      block.  Any exception raised inside the block is propagated after the
      cursor is closed.


.. _asyncpg-api-pool:

Connection Pools
================

.. autofunction:: asyncpg.pool.create_pool


.. autoclass:: asyncpg.pool.Pool()
   :members:


.. _asyncpg-api-record:

Record Objects
==============

Each row (or composite type value) returned by calls to ``fetch*`` methods
is represented by an instance of the :class:`~asyncpg.Record` object.
``Record`` objects are a tuple-/dict-like hybrid, and allow addressing of
items either by a numeric index or by a field name:

.. code-block:: pycon

    >>> import asyncpg
    >>> import asyncio
    >>> loop = asyncio.get_event_loop()
    >>> conn = loop.run_until_complete(asyncpg.connect())
    >>> r = loop.run_until_complete(conn.fetchrow('''
    ...     SELECT oid, rolname, rolsuper FROM pg_roles WHERE rolname = user'''))
    >>> r
    <Record oid=16388 rolname='elvis' rolsuper=True>
    >>> r['oid']
    16388
    >>> r[0]
    16388
    >>> dict(r)
    {'oid': 16388, 'rolname': 'elvis', 'rolsuper': True}
    >>> tuple(r)
    (16388, 'elvis', True)

.. note::

   ``Record`` objects currently cannot be created from Python code.

.. class:: Record()

   A read-only representation of PostgreSQL row.

   .. describe:: len(r)

      Return the number of fields in record *r*.

   .. describe:: r[field]

      Return the field of *r* with field name or index *field*.

   .. describe:: name in r

      Return ``True`` if record *r* has a field named *name*.

   .. describe:: iter(r)

      Return an iterator over the *values* of the record *r*.

   .. describe:: get(name[, default])

      Return the value for *name* if the record has a field named *name*,
      else return *default*. If *default* is not given, return ``None``.

      .. versionadded:: 0.18

   .. method:: values()

      Return an iterator over the record values.

   .. method:: keys()

      Return an iterator over the record field names.

   .. method:: items()

      Return an iterator over ``(field, value)`` pairs.


.. class:: ConnectionSettings()

    A read-only collection of Connection settings.

    .. describe:: settings.setting_name

       Return the value of the "setting_name" setting.  Raises an
       ``AttributeError`` if the setting is not defined.

       Example:

       .. code-block:: pycon

           >>> connection.get_settings().client_encoding
           'UTF8'


Data Types
==========

.. automodule:: asyncpg.types
   :members:
