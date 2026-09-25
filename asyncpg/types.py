# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0

from __future__ import annotations

import typing

from asyncpg.pgproto.types import (
    BitString, Point, Path, Polygon,
    Box, Line, LineSegment, Circle,
)

if typing.TYPE_CHECKING:
    from typing_extensions import Self


__all__ = (
    'Type', 'Attribute', 'Range', 'BitString', 'Point', 'Path', 'Polygon',
    'Box', 'Line', 'LineSegment', 'Circle', 'ServerVersion',
    'CopyProgress', 'CopyAbortHandle',
    'COPY_PHASE_STARTING', 'COPY_PHASE_SENDING', 'COPY_PHASE_DONE',
)


COPY_PHASE_STARTING: typing.Final = 'starting'
COPY_PHASE_SENDING: typing.Final = 'sending'
COPY_PHASE_DONE: typing.Final = 'done'


class CopyProgress(typing.NamedTuple):
    """Progress of a ``COPY ... FROM STDIN`` operation."""

    rows_count: int
    bytes_count: int
    phase: str


CopyProgress.__doc__ = 'Progress information of a COPY operation.'
CopyProgress.rows_count.__doc__ = 'Number of rows sent to the server.'
CopyProgress.bytes_count.__doc__ = \
    'Number of payload bytes sent in CopyData messages.'
CopyProgress.phase.__doc__ = (
    'The current phase of the COPY operation: '
    '"starting", "sending" or "done".')


class CopyAbortHandle:
    """A handle used to abort an in-progress ``COPY ... FROM STDIN``.

    Instances are created by the caller, passed to
    :meth:`asyncpg.Connection.copy_to_table` (or
    :meth:`asyncpg.Connection.copy_records_to_table`) via the
    *abort_handle* parameter, and can be signalled from any code by
    calling :meth:`abort`.
    """

    __slots__ = ('_context', '_pending')

    def __init__(self) -> None:
        self._context: typing.Any = None
        self._pending: bool = False

    def abort(self) -> None:
        """Request the associated COPY operation to be aborted.

        The request is cooperative: the COPY loop stops before sending
        the next data message and performs the COPY failure protocol,
        so that the server discards all data received during this COPY.
        """
        if self._context is not None:
            self._context.request_abort()
        else:
            # No COPY is currently using this handle; record the
            # request so that the next COPY bound to this handle
            # aborts immediately.
            self._pending = True

    @property
    def aborted(self) -> bool:
        """Whether :meth:`abort` has been requested."""
        if self._pending:
            return True
        context = self._context
        return context is not None and context.is_aborting()


class Type(typing.NamedTuple):
    oid: int
    name: str
    kind: str
    schema: str


Type.__doc__ = 'Database data type.'
Type.oid.__doc__ = 'OID of the type.'
Type.name.__doc__ = 'Type name.  For example "int2".'
Type.kind.__doc__ = \
    'Type kind.  Can be "scalar", "array", "composite" or "range".'
Type.schema.__doc__ = 'Name of the database schema that defines the type.'


class Attribute(typing.NamedTuple):
    name: str
    type: Type


Attribute.__doc__ = 'Database relation attribute.'
Attribute.name.__doc__ = 'Attribute name.'
Attribute.type.__doc__ = 'Attribute data type :class:`asyncpg.types.Type`.'


class ServerVersion(typing.NamedTuple):
    major: int
    minor: int
    micro: int
    releaselevel: str
    serial: int


ServerVersion.__doc__ = 'PostgreSQL server version tuple.'


class _RangeValue(typing.Protocol):
    def __eq__(self, __value: object) -> bool:
        ...

    def __lt__(self, __other: Self, /) -> bool:
        ...

    def __gt__(self, __other: Self, /) -> bool:
        ...


_RV = typing.TypeVar('_RV', bound=_RangeValue)


class Range(typing.Generic[_RV]):
    """Immutable representation of PostgreSQL `range` type."""

    __slots__ = ('_lower', '_upper', '_lower_inc', '_upper_inc', '_empty')

    _lower: _RV | None
    _upper: _RV | None
    _lower_inc: bool
    _upper_inc: bool
    _empty: bool

    def __init__(
        self,
        lower: _RV | None = None,
        upper: _RV | None = None,
        *,
        lower_inc: bool = True,
        upper_inc: bool = False,
        empty: bool = False
    ) -> None:
        self._empty = empty
        if empty:
            self._lower = self._upper = None
            self._lower_inc = self._upper_inc = False
        else:
            self._lower = lower
            self._upper = upper
            self._lower_inc = lower is not None and lower_inc
            self._upper_inc = upper is not None and upper_inc

    @property
    def lower(self) -> _RV | None:
        return self._lower

    @property
    def lower_inc(self) -> bool:
        return self._lower_inc

    @property
    def lower_inf(self) -> bool:
        return self._lower is None and not self._empty

    @property
    def upper(self) -> _RV | None:
        return self._upper

    @property
    def upper_inc(self) -> bool:
        return self._upper_inc

    @property
    def upper_inf(self) -> bool:
        return self._upper is None and not self._empty

    @property
    def isempty(self) -> bool:
        return self._empty

    def _issubset_lower(self, other: Self) -> bool:
        if other._lower is None:
            return True
        if self._lower is None:
            return False

        return self._lower > other._lower or (
            self._lower == other._lower
            and (other._lower_inc or not self._lower_inc)
        )

    def _issubset_upper(self, other: Self) -> bool:
        if other._upper is None:
            return True
        if self._upper is None:
            return False

        return self._upper < other._upper or (
            self._upper == other._upper
            and (other._upper_inc or not self._upper_inc)
        )

    def issubset(self, other: Self) -> bool:
        if self._empty:
            return True
        if other._empty:
            return False

        return self._issubset_lower(other) and self._issubset_upper(other)

    def issuperset(self, other: Self) -> bool:
        return other.issubset(self)

    def __bool__(self) -> bool:
        return not self._empty

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Range):
            return NotImplemented

        return (
            self._lower,
            self._upper,
            self._lower_inc,
            self._upper_inc,
            self._empty
        ) == (
            other._lower,  # pyright: ignore [reportUnknownMemberType]
            other._upper,  # pyright: ignore [reportUnknownMemberType]
            other._lower_inc,
            other._upper_inc,
            other._empty
        )

    def __hash__(self) -> int:
        return hash((
            self._lower,
            self._upper,
            self._lower_inc,
            self._upper_inc,
            self._empty
        ))

    def __repr__(self) -> str:
        if self._empty:
            desc = 'empty'
        else:
            if self._lower is None or not self._lower_inc:
                lb = '('
            else:
                lb = '['

            if self._lower is not None:
                lb += repr(self._lower)

            if self._upper is not None:
                ub = repr(self._upper)
            else:
                ub = ''

            if self._upper is None or not self._upper_inc:
                ub += ')'
            else:
                ub += ']'

            desc = '{}, {}'.format(lb, ub)

        return '<Range {}>'.format(desc)

    __str__ = __repr__
