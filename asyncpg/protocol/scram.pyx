# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import base64
import hashlib
import hmac
import re
import secrets
import stringprep
import unicodedata


# Signature algorithm OIDs of X.509 certificates whose hash algorithm is
# strong enough to be reused directly for the RFC 5929
# "tls-server-end-point" channel binding.  This mirrors the table used by
# PostgreSQL and libpq (OBJ_find_sigid_algs() in OpenSSL): only SHA-256,
# SHA-384 and SHA-512 are selected, every other signature algorithm
# (MD5, SHA-1, SHA-224, RSASSA-PSS, EdDSA, ...) falls back to SHA-256.
_TLS_SERVER_END_POINT_HASH_BY_OID = {
    # sha256WithRSAEncryption, sha384WithRSAEncryption,
    # sha512WithRSAEncryption
    '1.2.840.113549.1.1.11': 'sha256',
    '1.2.840.113549.1.1.12': 'sha384',
    '1.2.840.113549.1.1.13': 'sha512',
    # ecdsa-with-SHA256/384/512
    '1.2.840.10045.4.3.2': 'sha256',
    '1.2.840.10045.4.3.3': 'sha384',
    '1.2.840.10045.4.3.4': 'sha512',
    # dsa-with-sha256/384/512
    '2.16.840.1.101.3.4.3.2': 'sha256',
    '2.16.840.1.101.3.4.3.3': 'sha384',
    '2.16.840.1.101.3.4.3.4': 'sha512',
}


def _read_der_element_length(bytes data, int offset):
    """Read a DER length at *offset*, return (length, next_offset)."""
    cdef:
        int first
        int num
        int length

    first = data[offset]
    if first & 0x80:
        num = first & 0x7f
        if num == 0 or num > 4:
            raise ValueError('invalid DER length in X.509 certificate')
        length = 0
        for i in range(num):
            length = (length << 8) | data[offset + 1 + i]
        return length, offset + 1 + num
    return first, offset + 1


def _decode_der_oid(bytes oid_bytes):
    """Decode DER OID content octets into dotted-decimal text."""
    cdef:
        list parts
        object value
        int byte

    if not oid_bytes:
        raise ValueError('empty OID in X.509 certificate')

    parts = [str(oid_bytes[0] // 40), str(oid_bytes[0] % 40)]
    value = 0
    for byte in oid_bytes[1:]:
        value = (value << 7) | (byte & 0x7f)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return '.'.join(parts)


def _read_x509_signature_algorithm_oid(bytes cert_der):
    """Return the signatureAlgorithm OID (dotted text) of a DER X.509 cert.

    The certificate has the following structure (RFC 5280)::

        Certificate ::= SEQUENCE {
            tbsCertificate      TBSCertificate,
            signatureAlgorithm  AlgorithmIdentifier,
            signatureValue      BIT STRING }

    Only a minimal traversal is needed: skip the outer SEQUENCE and the
    tbsCertificate SEQUENCE, then read the OID of the following
    AlgorithmIdentifier.
    """
    cdef:
        int pos
        int tbs_len
        int sig_algo_start
        int oid_len
        int oid_pos

    if not cert_der or cert_der[0] != 0x30:
        raise ValueError(
            'invalid X.509 certificate: expected an outer DER SEQUENCE')

    _, pos = _read_der_element_length(cert_der, 1)

    if cert_der[pos] != 0x30:
        raise ValueError(
            'invalid X.509 certificate: missing tbsCertificate SEQUENCE')
    tbs_len, pos = _read_der_element_length(cert_der, pos + 1)
    pos += tbs_len

    if cert_der[pos] != 0x30:
        raise ValueError(
            'invalid X.509 certificate: missing signatureAlgorithm')
    _, sig_algo_start = _read_der_element_length(cert_der, pos + 1)

    # The first member of AlgorithmIdentifier is the algorithm OID.
    if cert_der[sig_algo_start] != 0x06:
        raise ValueError(
            'invalid X.509 certificate: signatureAlgorithm is not an OID')
    oid_len, oid_pos = _read_der_element_length(
        cert_der, sig_algo_start + 1)
    return _decode_der_oid(cert_der[oid_pos:oid_pos + oid_len])


def _build_tls_server_end_point_binding(bytes cert_der):
    """Build the RFC 5929 tls-server-end-point channel binding data.

    The DER-encoded server certificate is hashed with the digest used by
    the certificate's own signature algorithm, except that weak (MD5,
    SHA-1) or otherwise unsupported digests are replaced by SHA-256,
    matching PostgreSQL and libpq.
    """
    cdef:
        str sig_oid
        str hash_name

    sig_oid = _read_x509_signature_algorithm_oid(cert_der)
    hash_name = _TLS_SERVER_END_POINT_HASH_BY_OID.get(sig_oid, 'sha256')
    return hashlib.new(hash_name, cert_der).digest()


@cython.final
cdef class SCRAMAuthentication:
    """Contains the protocol for generating and a SCRAM hashed password.

    Since PostgreSQL 10, the option to hash passwords using the SCRAM-SHA-256
    method was added. This module follows the defined protocol, which can be
    referenced from here:

    https://www.postgresql.org/docs/current/sasl-authentication.html#SASL-SCRAM-SHA-256

    libpq references the following RFCs that it uses for implementation:

        * RFC 5802
        * RFC 5803
        * RFC 7677

    The protocol works as such:

    - A client connets to the server. The server requests the client to begin
    SASL authentication using SCRAM and presents a client with the methods it
    supports. At present, those are SCRAM-SHA-256, and, on servers that are
    built with OpenSSL and
    are PG11+, SCRAM-SHA-256-PLUS (which supports channel binding, more on that
    below)

    - The client sends a "first message" to the server, where it chooses which
    method to authenticate with, and sends, along with the method, an indication
    of channel binding (the GS2 header), a nonce, and the username.
    (Technically, PostgreSQL ignores the username as it already has it from the
    initical connection, but we add it for completeness)

    - The server responds with a "first message" in which it extends the nonce,
    as well as a password salt and the number of iterations to hash the password
    with. The client validates that the new nonce contains the first part of the
    client's original nonce

    - The client generates a salted password, but does not sent this up to the
    server. Instead, the client follows the SCRAM algorithm (RFC5802) to
    generate a proof. This proof is sent aspart of a client "final message" to
    the server for it to validate.

    - The server validates the proof. If it is valid, the server sends a
    verification code for the client to verify that the server came to the same
    proof the client did. PostgreSQL immediately sends an AuthenticationOK
    response right after a valid negotiation. If the password the client
    provided was invalid, then authentication fails.

    (The beauty of this is that the salted password is never transmitted over
    the wire!)

    PostgreSQL 11 added support for channel binding (i.e.
    SCRAM-SHA-256-PLUS).  When that mechanism is selected over an encrypted
    connection, the GS2 header is "p=tls-server-end-point,," and the
    channel-binding field of the final message carries the RFC 5929
    "tls-server-end-point" data, i.e. a hash of the DER-encoded server
    certificate.  On an encrypted connection that ended up using the plain
    SCRAM-SHA-256 mechanism, the GS2 flag is "y" (the client supports
    channel binding but believes the server does not); otherwise the flag
    is "n".
    """
    SCRAM_SHA_256 = b"SCRAM-SHA-256"
    SCRAM_SHA_256_PLUS = b"SCRAM-SHA-256-PLUS"
    TLS_SERVER_END_POINT = b"tls-server-end-point"
    AUTHENTICATION_METHODS = [SCRAM_SHA_256]
    # mechanism name -> channel binding type name (RFC 5929)
    CHANNEL_BINDING_METHODS = {SCRAM_SHA_256_PLUS: TLS_SERVER_END_POINT}
    DEFAULT_CLIENT_NONCE_BYTES = 24
    DIGEST = hashlib.sha256
    REQUIREMENTS_CLIENT_FINAL_MESSAGE = ['client_channel_binding',
        'server_nonce']
    REQUIREMENTS_CLIENT_PROOF = ['password_iterations', 'password_salt',
        'server_first_message', 'server_nonce']
    SASLPREP_PROHIBITED = (
        stringprep.in_table_a1, # PostgreSQL treats this as prohibited
        stringprep.in_table_c12,
        stringprep.in_table_c21_c22,
        stringprep.in_table_c3,
        stringprep.in_table_c4,
        stringprep.in_table_c5,
        stringprep.in_table_c6,
        stringprep.in_table_c7,
        stringprep.in_table_c8,
        stringprep.in_table_c9,
    )

    def __cinit__(self, bytes authentication_method,
                  bytes channel_binding_data=None,
                  bint supports_channel_binding=False):
        self.authentication_method = authentication_method
        self.authorization_message = None
        self.client_first_message_bare = None
        self.client_nonce = None
        self.client_proof = None
        self.password_salt = None
        # self.password_iterations = None
        self.server_first_message = None
        self.server_key = None
        self.server_nonce = None

        # Build the GS2 header and the channel binding data used in the
        # "c=" attribute of the final message, following the rules in
        # RFC 5802 section 6 and the tls-server-end-point definition in
        # RFC 5929.
        channel_binding_type = self.CHANNEL_BINDING_METHODS.get(
            authentication_method)
        if channel_binding_type is not None:
            if not channel_binding_data:
                raise ValueError(
                    "channel binding data is required for the "
                    "{!r} authentication mechanism".format(
                        authentication_method))
            self.gs2_header = b"p=" + channel_binding_type + b",,"
            # cbind-input = gs2-header immediately followed by the
            # channel binding data (same layout as in libpq).
            self.client_channel_binding = \
                self.gs2_header + channel_binding_data
        else:
            # "y" means that this client supports channel binding, but
            # believes that the server does not (the negotiated
            # mechanism is not a -PLUS one even though the connection
            # is encrypted).
            self.gs2_header = b"y,," if supports_channel_binding else b"n,,"
            self.client_channel_binding = self.gs2_header

    cpdef create_client_first_message(self, str username):
        """Create the initial client message for SCRAM authentication"""
        cdef:
            bytes msg
            bytes client_first_message

        self.client_nonce = \
            self._generate_client_nonce(self.DEFAULT_CLIENT_NONCE_BYTES)
        # set the client first message bare here, as it's used in a later step
        self.client_first_message_bare =  b"n=" + username.encode("utf-8") + \
            b",r=" + self.client_nonce
        # put together the full message here
        msg = bytes()
        msg += self.authentication_method + b"\0"
        client_first_message = self.gs2_header + \
            self.client_first_message_bare
        msg += (len(client_first_message)).to_bytes(4, byteorder='big') + \
            client_first_message
        return msg

    cpdef create_client_final_message(self, str password):
        """Create the final client message as part of SCRAM authentication"""
        cdef:
            bytes msg

        if any([getattr(self, val) is None for val in
                self.REQUIREMENTS_CLIENT_FINAL_MESSAGE]):
            raise Exception(
                "you need values from server to generate a client proof")

        # normalize the password using the SASLprep algorithm in RFC 4013
        password = self._normalize_password(password)

        # generate the client proof
        self.client_proof = self._generate_client_proof(password=password)
        msg = bytes()
        msg += b"c=" + base64.b64encode(self.client_channel_binding) + \
            b",r=" + self.server_nonce + \
            b",p=" + base64.b64encode(self.client_proof)
        return msg

    cpdef parse_server_first_message(self, bytes server_response):
        """Parse the response from the first message from the server"""
        self.server_first_message = server_response
        try:
            self.server_nonce = re.search(b'r=([^,]+),',
                self.server_first_message).group(1)
        except IndexError:
            raise Exception("could not get nonce")
        if not self.server_nonce.startswith(self.client_nonce):
            raise Exception("invalid nonce")
        try:
            self.password_salt = re.search(b',s=([^,]+),',
                self.server_first_message).group(1)
        except IndexError:
            raise Exception("could not get salt")
        try:
            self.password_iterations = int(re.search(b',i=(\d+),?',
                self.server_first_message).group(1))
        except (IndexError, TypeError, ValueError):
            raise Exception("could not get iterations")

    cpdef bint verify_server_final_message(self, bytes server_final_message):
        """Verify the final message from the server"""
        cdef:
            bytes server_signature

        try:
            server_signature = re.search(b'v=([^,]+)',
                server_final_message).group(1)
        except IndexError:
            raise Exception("could not get server signature")

        verify_server_signature = hmac.new(self.server_key.digest(),
            self.authorization_message, self.DIGEST)
        # validate the server signature against the verifier
        return server_signature == base64.b64encode(
            verify_server_signature.digest())

    cdef _bytes_xor(self, bytes a, bytes b):
        """XOR two bytestrings together"""
        return bytes(a_i ^ b_i for a_i, b_i in zip(a, b))

    cdef _generate_client_nonce(self, int num_bytes):
        cdef:
            bytes token

        token = secrets.token_bytes(num_bytes)

        return base64.b64encode(token)

    cdef _generate_client_proof(self, str password):
        """need to ensure a server response exists, i.e. """
        cdef:
            bytes salted_password

        if any([getattr(self, val) is None for val in
                self.REQUIREMENTS_CLIENT_PROOF]):
            raise Exception(
                "you need values from server to generate a client proof")
        # generate a salt password
        salted_password = self._generate_salted_password(password,
            self.password_salt, self.password_iterations)
        # client key is derived from the salted password
        client_key = hmac.new(salted_password, b"Client Key", self.DIGEST)
        # this allows us to compute the stored key that is residing on the server
        stored_key = self.DIGEST(client_key.digest())
        # as well as compute the server key
        self.server_key = hmac.new(salted_password, b"Server Key", self.DIGEST)
        # build the authorization message that will be used in the
        # client signature; the channel binding value in the "c="
        # attribute is the same one sent in the client final message
        self.authorization_message = self.client_first_message_bare + b"," + \
            self.server_first_message + b",c=" + \
            base64.b64encode(self.client_channel_binding) + \
            b",r=" +  self.server_nonce
        # sign!
        client_signature = hmac.new(stored_key.digest(),
            self.authorization_message, self.DIGEST)
        # and the proof
        return self._bytes_xor(client_key.digest(), client_signature.digest())

    cdef _generate_salted_password(self, str password, bytes salt, int iterations):
        """This follows the "Hi" algorithm specified in RFC5802"""
        cdef:
            bytes p
            bytes s
            bytes u

        # convert the password to a binary string - UTF8 is safe for SASL
        # (though there are SASLPrep rules)
        p = password.encode("utf8")
        # the salt needs to be base64 decoded -- full binary must be used
        s = base64.b64decode(salt)
        # the initial signature is the salt with a terminator of a 32-bit string
        # ending in 1
        ui = hmac.new(p, s + b'\x00\x00\x00\x01', self.DIGEST)
        # grab the initial digest
        u = ui.digest()
        # for X number of iterations, recompute the HMAC signature against the
        # password and the latest iteration of the hash, and XOR it with the
        # previous version
        for x in range(iterations - 1):
            ui = hmac.new(p, ui.digest(), hashlib.sha256)
            # this is a fancy way of XORing two byte strings together
            u = self._bytes_xor(u, ui.digest())
        return u

    cdef _normalize_password(self, str original_password):
        """Normalize the password using the SASLprep from RFC4013"""
        cdef:
            str normalized_password

        # Note: Per the PostgreSQL documentation, PostgreSWL does not require
        # UTF-8 to be used for the password, but will perform SASLprep on the
        # password regardless.
        # If the password is not valid UTF-8, PostgreSQL will then **not** use
        # SASLprep processing.
        # If the password fails SASLprep, the password should still be sent
        # See: https://www.postgresql.org/docs/current/sasl-authentication.html
        # and
        # https://git.postgresql.org/gitweb/?p=postgresql.git;a=blob;f=src/common/saslprep.c
        # using the `pg_saslprep` function
        normalized_password = original_password
        # if the original password is an ASCII string or fails to encode as a
        # UTF-8 string, then no further action is needed
        try:
            original_password.encode("ascii")
        except UnicodeEncodeError:
            pass
        else:
            return original_password

        # Step 1 of SASLPrep: Map. Per the algorithm, we map non-ascii space
        # characters to ASCII spaces (\x20 or \u0020, but we will use ' ') and
        # commonly mapped to nothing characters are removed
        # Table C.1.2 -- non-ASCII spaces
        # Table B.1 -- "Commonly mapped to nothing"
        normalized_password = u"".join(
            ' ' if stringprep.in_table_c12(c) else c
            for c in tuple(normalized_password) if not stringprep.in_table_b1(c)
        )

        # If at this point the password is empty, PostgreSQL uses the original
        # password
        if not normalized_password:
            return original_password

        # Step 2 of SASLPrep: Normalize. Normalize the password using the
        # Unicode normalization algorithm to NFKC form
        normalized_password = unicodedata.normalize('NFKC', normalized_password)

        # If the password is not empty, PostgreSQL uses the original password
        if not normalized_password:
            return original_password

        normalized_password_tuple = tuple(normalized_password)

        # Step 3 of SASLPrep: Prohobited characters. If PostgreSQL detects any
        # of the prohibited characters in SASLPrep, it will use the original
        # password
        # We also include "unassigned code points" in the prohibited character
        # category as PostgreSQL does the same
        for c in normalized_password_tuple:
            if any(
                in_prohibited_table(c)
                for in_prohibited_table in self.SASLPREP_PROHIBITED
            ):
                return original_password

        # Step 4 of SASLPrep: Bi-directional characters. PostgreSQL follows the
        # rules for bi-directional characters laid on in RFC3454 Sec. 6 which
        # are:
        # 1. Characters in RFC 3454 Sec 5.8 are prohibited (C.8)
        # 2. If a string contains a RandALCat character, it cannot containy any
        #    LCat character
        # 3. If the string contains any RandALCat character, an RandALCat
        #    character must be the first and last character of the string
        # RandALCat characters are found in table D.1, whereas LCat are in D.2
        if any(stringprep.in_table_d1(c) for c in normalized_password_tuple):
            # if the first character or the last character are not in D.1,
            # return the original password
            if not (stringprep.in_table_d1(normalized_password_tuple[0]) and
                    stringprep.in_table_d1(normalized_password_tuple[-1])):
                return original_password

            # if any characters are in D.2, use the original password
            if any(
                stringprep.in_table_d2(c) for c in normalized_password_tuple
            ):
                return original_password

        # return the normalized password
        return normalized_password
