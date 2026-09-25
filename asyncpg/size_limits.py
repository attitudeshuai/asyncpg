# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


"""Client-side size limits for requests and server responses.

A :class:`~asyncpg.SizeLimits` value holds four independent limits:

* ``query_max_length`` -- the maximum encoded length, in bytes, of a
  query text;
* ``parameter_max_length`` -- the maximum encoded length, in bytes, of a
  single query parameter;
* ``row_max_length`` -- the maximum length, in bytes, of a single result
  row (a ``DataRow`` protocol message payload);
* ``message_max_length`` -- the maximum length, in bytes, of any single
  PostgreSQL protocol message (including its framing).

``None`` (the default for every field) means that no limit is enforced
and that asyncpg behaves as if size limits were not configured.

The same :class:`~asyncpg.SizeLimits` instance can be passed to
:func:`~asyncpg.connect`/:func:`~asyncpg.create_pool` (in which case it
applies to every operation on the connection(s)) or to an individual
query method via its ``size_limits`` keyword argument (in which case it
is used for that call only).
"""

from __future__ import annotations

import collections
import typing


# Every size-bearing quantity below is ultimately backed by a 32-bit
# length field of the PostgreSQL wire protocol, so a configured limit
# above that value can never be meaningful and is rejected as a
# conflicting configuration.
MAX_SIZE_LIMIT = 0x7FFFFFFF


_FIELDS = (
    'query_max_length',
    'parameter_max_length',
    'row_max_length',
    'message_max_length',
)


def _validate(name: str, value: typing.Any) -> None:
    if value is None:
        return

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            '{} is expected to be an int or None, got {!r}'.format(
                name, value))

    if value < 0:
        raise ValueError(
            '{} is expected to be greater than or equal to 0, '
            'got {!r}'.format(name, value))

    if value > MAX_SIZE_LIMIT:
        raise ValueError(
            '{} is expected to be at most {} bytes (the maximum size '
            'representable in the PostgreSQL protocol), got {!r}'.format(
                name, MAX_SIZE_LIMIT, value))


_SizeLimitsBase = collections.namedtuple(
    '_SizeLimitsBase',
    [
        'query_max_length',
        'parameter_max_length',
        'row_max_length',
        'message_max_length',
    ],
    defaults=(None, None, None, None),
)


class SizeLimits(_SizeLimitsBase):
    """Configurable size limits enforced by the client.

    All fields are optional; ``None`` (the default) means "unlimited".

    :param int query_max_length:
        Maximum length, in bytes, of an encoded query text.
    :param int parameter_max_length:
        Maximum length, in bytes, of a single encoded query parameter.
    :param int row_max_length:
        Maximum length, in bytes, of a single result row.
    :param int message_max_length:
        Maximum length, in bytes, of a single protocol message.
    """

    __slots__ = ()

    def __new__(
        cls,
        query_max_length: typing.Optional[int] = None,
        parameter_max_length: typing.Optional[int] = None,
        row_max_length: typing.Optional[int] = None,
        message_max_length: typing.Optional[int] = None,
    ) -> 'SizeLimits':
        for field_name, field_value in (
            ('query_max_length', query_max_length),
            ('parameter_max_length', parameter_max_length),
            ('row_max_length', row_max_length),
            ('message_max_length', message_max_length),
        ):
            _validate(field_name, field_value)

        return super().__new__(
            cls,
            query_max_length,
            parameter_max_length,
            row_max_length,
            message_max_length,
        )

    def replace(self, **kwargs: typing.Any) -> 'SizeLimits':
        """Return a copy with the given fields replaced."""
        unknown = kwargs.keys() - _FIELDS
        if unknown:
            raise TypeError(
                'unexpected SizeLimits field(s): {}'.format(
                    ', '.join(sorted(unknown))))
        return self._replace(**kwargs)
