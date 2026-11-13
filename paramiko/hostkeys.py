# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.


import binascii
import os
import re
import struct
import time
from base64 import decodebytes, encodebytes
from collections.abc import MutableMapping
from hashlib import sha1
from hmac import HMAC

from paramiko.message import Message
from paramiko.pkey import PKey, UnknownKeyType
from paramiko.ssh_exception import SSHException
from paramiko.util import b, constant_time_bytes_eq, get_logger, u


# OpenSSH known_hosts line markers.  Only one may prefix a line.
CA_MARKER = "cert-authority"
REVOKE_MARKER = "revoked"
_MARKERS = (CA_MARKER, REVOKE_MARKER)

# OpenSSH certificate suffix & the certificate's "type" field values (see
# PROTOCOL.certkeys in openssh-portable).
_CERT_SUFFIX = "-cert-v01@openssh.com"
CERT_TYPE_USER = 1
CERT_TYPE_HOST = 2


def _match_pattern(string, pattern):
    """
    OpenSSH-style single-pattern match.

    ``*`` matches any run of characters, ``?`` matches exactly one character,
    and everything else is literal (notably, unlike fnmatch, ``[`` is not
    special).  Matching is case-sensitive; callers choose whether to fold case.

    Implemented as the classic iterative wildcard matcher rather than via
    ``re`` so that untrusted input (e.g. certificate principals) cannot trigger
    catastrophic regex backtracking.
    """
    s = p = 0
    star_p = -1
    star_s = 0
    while s < len(string):
        if p < len(pattern) and pattern[p] in ("?", string[s]):
            s += 1
            p += 1
        elif p < len(pattern) and pattern[p] == "*":
            # Remember where the '*' was, and try consuming zero chars first.
            star_p = p
            star_s = s
            p += 1
        elif star_p != -1:
            # Backtrack: let the last '*' swallow one more character.
            star_s += 1
            s = star_s
            p = star_p + 1
        else:
            return False
    # Trailing '*'s may match the (now empty) remainder.
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def _match_pattern_list(string, patterns, lower=True):
    """
    Match a string against a comma-separated OpenSSH pattern list, where any
    subpattern may be negated with a leading ``!``.

    Returns ``-1`` if a negated subpattern matched (i.e. veto), ``1`` if a
    positive subpattern matched, or ``0`` if nothing matched - mirroring
    OpenSSH's ``match_pattern_list``.
    """
    if lower:
        string = string.lower()
    matched = 0
    for sub in patterns.split(","):
        negated = sub.startswith("!")
        if negated:
            sub = sub[1:]
        if lower:
            sub = sub.lower()
        if _match_pattern(string, sub):
            if negated:
                return -1
            matched = 1
    return matched


def _match_hostname(hostname, patterns):
    """
    OpenSSH ``match_hostname``: case-insensitive, negation-aware pattern-list
    match against a known_hosts hostname field.
    """
    return _match_pattern_list(hostname, patterns, lower=True)


def _hostname_candidates(hostname):
    """
    Return the names to try matching for ``hostname``.

    OpenSSH looks up non-default ports as ``[host]:port``.  CA/revoked lines
    are commonly written against the bare host (and are not port-specific), so
    allow either spelling: the name as given, plus the unbracketed host if the
    name is in ``[host]:port`` form.
    """
    candidates = [hostname]
    match = re.fullmatch(r"\[([^\[\]]*)\]:([0-9]+)", hostname)
    if match is not None:
        candidates.append(match.group(1))
    return candidates


class _CertReader:
    """
    Minimal, strict SSH wire-format reader for certificate blobs.

    `.Message` deliberately pads short reads with NULs (it is used for network
    data where that is a long-standing quirk); for certificates, truncation
    must instead invalidate the whole certificate, so bounds are checked here.
    """

    def __init__(self, data):
        self._data = data
        self._pos = 0

    def _take(self, n):
        end = self._pos + n
        if n < 0 or end > len(self._data):
            raise SSHException("Truncated certificate")
        out = self._data[self._pos : end]
        self._pos = end
        return out

    def get_bytes(self, n):
        return self._take(n)

    def get_string(self):
        return self._take(self.get_uint32())

    def get_uint32(self):
        return struct.unpack(">I", self._take(4))[0]

    def get_uint64(self):
        return struct.unpack(">Q", self._take(8))[0]

    def get_so_far(self):
        return self._data[: self._pos]

    def get_remainder(self):
        return self._data[self._pos :]

    def at_end(self):
        return self._pos == len(self._data)


class _CertificateInfo:
    """
    The subset of an OpenSSH certificate needed to decide whether a host
    certificate is trustworthy.  See PROTOCOL.certkeys in openssh-portable.
    """

    def __init__(
        self,
        cert_type,
        principals,
        valid_after,
        valid_before,
        critical,
        ca_key,
        signed_data,
        signature,
    ):
        self.cert_type = cert_type
        self.principals = principals
        self.valid_after = valid_after
        self.valid_before = valid_before
        self.critical = critical
        self.ca_key = ca_key
        # Exact bytes covered by the CA's signature, and the signature blob.
        self.signed_data = signed_data
        self.signature = signature

    @classmethod
    def from_pkey(cls, key):
        """
        Parse the certificate attached to ``key`` (via its ``.public_blob``).

        Returns ``None`` if ``key`` is not certificate-bearing, or if the
        certificate is malformed or uses a key type we don't understand; an
        unparseable certificate is simply untrusted, never an error during
        host key checking.
        """
        blob = getattr(key, "public_blob", None)
        if blob is None or not blob.key_type.endswith(_CERT_SUFFIX):
            return None
        try:
            return cls.from_blob(blob.key_type, blob.key_blob, key)
        except Exception:
            return None

    @classmethod
    def from_blob(cls, key_type, blob, key):
        m = _CertReader(blob)
        if m.get_string() != key_type.encode():
            raise SSHException("Certificate key type mismatch")
        # The nonce is followed by the subject's public key fields, which are
        # byte-identical to the plain key blob minus its leading type string.
        # Use the already-parsed PKey for those and verify alignment.
        m.get_string()  # nonce
        plain = _CertReader(key.asbytes())
        plain.get_string()  # plain key type
        key_fields = plain.get_remainder()
        if m.get_bytes(len(key_fields)) != key_fields:
            raise SSHException("Certificate subject key mismatch")

        m.get_uint64()  # serial
        cert_type = m.get_uint32()
        m.get_string()  # key id
        principals = cls._parse_string_list(m.get_string())
        valid_after = m.get_uint64()
        valid_before = m.get_uint64()
        critical = cls._parse_string_pairs(m.get_string())
        cls._parse_string_pairs(m.get_string())  # extensions
        m.get_string()  # reserved
        signature_key_blob = m.get_string()
        # OpenSSH signs the entire certificate blob up to (but not including)
        # the signature string - i.e. everything consumed so far.
        signed_data = m.get_so_far()
        signature = m.get_string()
        if not m.at_end():
            raise SSHException("Trailing data in certificate")

        sig_key_msg = _CertReader(signature_key_blob)
        ca_key = PKey.from_type_string(
            sig_key_msg.get_string().decode(), signature_key_blob
        )
        return cls(
            cert_type=cert_type,
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            critical=critical,
            ca_key=ca_key,
            signed_data=signed_data,
            signature=signature,
        )

    @staticmethod
    def _parse_string_list(blob):
        m = _CertReader(blob)
        ret = []
        while not m.at_end():
            ret.append(m.get_string().decode())
        return ret

    @staticmethod
    def _parse_string_pairs(blob):
        m = _CertReader(blob)
        ret = []
        while not m.at_end():
            name = m.get_string().decode()
            value = m.get_string()
            ret.append((name, value))
        return ret

    def verify(self, hostname, now=None):
        """
        Validate this certificate for ``hostname``.

        Requires a verifiable CA signature, host certificate type, a current
        validity window, a non-empty principal list containing ``hostname``,
        and no critical options (paramiko implements none, so any we see are
        by definition unsupported).  Returns a `bool`.
        """
        if self.cert_type != CERT_TYPE_HOST:
            return False
        # We implement no critical options, so - like OpenSSH for host
        # certificates - refuse anything carrying one rather than ignore it.
        if self.critical:
            return False
        if now is None:
            now = time.time()
        if now < self.valid_after or now >= self.valid_before:
            return False
        if not self.principals:
            return False
        # Certificate principals name hosts, not known_hosts lookup keys, so
        # match against the plain hostname: OpenSSH passes the raw hostname
        # here, while the known_hosts key for a non-default port is the
        # "[host]:port" spelling.
        names = _hostname_candidates(hostname)
        bare_host = names[-1] if len(names) > 1 else names[0]
        # As in OpenSSH, principals support wildcards and are matched
        # case-sensitively, with no negation semantics.
        if not any(
            _match_pattern(bare_host, principal)
            for principal in self.principals
        ):
            return False
        try:
            return bool(
                self.ca_key.verify_ssh_sig(
                    self.signed_data, Message(self.signature)
                )
            )
        except Exception:
            # Any malformed or failed verification means "not trusted".
            return False


class HostKeys(MutableMapping):
    """
    Representation of an OpenSSH-style "known hosts" file.  Host keys can be
    read from one or more files, and then individual hosts can be looked up to
    verify server keys during SSH negotiation.

    A `.HostKeys` object can be treated like a dict; any dict lookup is
    equivalent to calling `lookup`.

    .. versionadded:: 1.5.3
    """

    def __init__(self, filename=None):
        """
        Create a new HostKeys object, optionally loading keys from an OpenSSH
        style host-key file.

        :param str filename: filename to load host keys from, or ``None``
        """
        # emulate a dict of { hostname: { keytype: PKey } }
        self._entries = []
        if filename is not None:
            self.load(filename)

    def add(self, hostname, keytype, key):
        """
        Add a host key entry to the table.  Any existing entry for a
        ``(hostname, keytype)`` pair will be replaced.

        :param str hostname: the hostname (or IP) to add
        :param str keytype: key type (in ``"ssh-<type>"`` format)
        :param .PKey key: the key to add
        """
        for e in self._entries:
            if (
                e.marker is None
                and (hostname in e.hostnames)
                and e.key.get_name() == keytype
            ):
                e.key = key
                return
        self._entries.append(HostKeyEntry([hostname], key))

    def load(self, filename):
        """
        Read a file of known SSH host keys, in the format used by OpenSSH.
        This type of file unfortunately doesn't exist on Windows, but on
        posix, it will usually be stored in
        ``os.path.expanduser("~/.ssh/known_hosts")``.

        If this method is called multiple times, the host keys are merged,
        not cleared.  So multiple calls to `load` will just call `add`,
        replacing any existing entries and adding new ones.

        :param str filename: name of the file to read host keys from

        :raises: ``IOError`` -- if there was an error reading the file
        """
        with open(filename, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if (len(line) == 0) or (line[0] == "#"):
                    continue
                try:
                    entry = HostKeyEntry.from_line(line, lineno)
                except SSHException:
                    continue
                if entry is not None:
                    # Marked (@cert-authority / @revoked) lines are policy
                    # rules, not pinned key records; never de-duplicate them
                    # against existing entries, just keep them verbatim.
                    if entry.marker is None:
                        _hostnames = entry.hostnames
                        for h in _hostnames:
                            # Only consult pinned entries here: policy lines
                            # must not influence ordinary de-duplication.
                            if self._check_pinned(h, entry.key):
                                entry.hostnames.remove(h)
                    if len(entry.hostnames):
                        self._entries.append(entry)

    def save(self, filename):
        """
        Save host keys into a file, in the format used by OpenSSH.  The order
        of keys in the file will be preserved when possible (if these keys were
        loaded from a file originally).  The single exception is that combined
        lines will be split into individual key lines, which is arguably a bug.

        :param str filename: name of the file to write

        :raises: ``IOError`` -- if there was an error writing the file

        .. versionadded:: 1.6.1
        """
        with open(filename, "w") as f:
            for e in self._entries:
                line = e.to_line()
                if line:
                    f.write(line)

    def lookup(self, hostname):
        """
        Find a hostkey entry for a given hostname or IP.  If no entry is found,
        ``None`` is returned.  Otherwise a dictionary of keytype to key is
        returned.

        :param str hostname: the hostname (or IP) to lookup
        :return: dict of `str` -> `.PKey` keys associated with this host
            (or ``None``)
        """

        class SubDict(MutableMapping):
            def __init__(self, hostname, entries, hostkeys):
                self._hostname = hostname
                self._entries = entries
                self._hostkeys = hostkeys

            def __iter__(self):
                for k in self.keys():
                    yield k

            def __len__(self):
                return len(self.keys())

            def __delitem__(self, key):
                for e in list(self._entries):
                    if e.key.get_name() == key:
                        self._entries.remove(e)
                        break
                else:
                    raise KeyError(key)

            def __getitem__(self, key):
                for e in self._entries:
                    if e.key.get_name() == key:
                        return e.key
                raise KeyError(key)

            def __setitem__(self, key, val):
                for e in self._entries:
                    if e.key is None:
                        continue
                    if e.key.get_name() == key:
                        # replace
                        e.key = val
                        break
                else:
                    # add a new one
                    e = HostKeyEntry([hostname], val)
                    self._entries.append(e)
                    self._hostkeys._entries.append(e)

            def keys(self):
                return [
                    e.key.get_name()
                    for e in self._entries
                    if e.key is not None
                ]

        entries = []
        for e in self._entries:
            # CA and revoked lines are policy, not pinned host keys; they are
            # consulted by `check` and never surfaced through `lookup`.
            if e.marker is not None:
                continue
            if self._hostname_matches(hostname, e):
                entries.append(e)
        if len(entries) == 0:
            return None
        return SubDict(hostname, entries, self)

    def _hostname_matches(self, hostname, entry):
        """
        Tests whether ``hostname`` string matches given SubDict ``entry``.

        Plain hostname fields are exact matches (or hashed comparisons), as
        before.  Marked (``@cert-authority`` / ``@revoked``) entries instead
        follow OpenSSH hostname pattern semantics: ``*``/``?`` wildcards,
        comma-separated lists, and ``!`` negation over the whole field.

        :returns bool:
        """
        if entry.marker is not None:
            field = ",".join(entry.hostnames)
            results = []
            for candidate in _hostname_candidates(hostname):
                if field.startswith("|1|"):
                    # As in OpenSSH's match_maybe_hashed: a hashed field is
                    # compared by hash, anything else by hostname pattern.
                    ok = (
                        not candidate.startswith("|1|")
                        and constant_time_bytes_eq(
                            self.hash_host(candidate, field), field
                        )
                    )
                    results.append(1 if ok else 0)
                else:
                    results.append(_match_hostname(candidate, field))
            # A negation anywhere vetoes every other (partial) match.
            return -1 not in results and 1 in results
        for h in entry.hostnames:
            if (
                h == hostname
                or h.startswith("|1|")
                and not hostname.startswith("|1|")
                and constant_time_bytes_eq(self.hash_host(hostname, h), h)
            ):
                return True
        return False

    def _lookup_entries(self, hostname):
        """
        All entries whose hostnames match ``hostname``, markers included.
        """
        return [
            e for e in self._entries if self._hostname_matches(hostname, e)
        ]

    def _is_revoked(self, hostname, key):
        """
        True if ``key`` - or, for a certificate, its signing CA - is explicitly
        revoked for ``hostname``.  Revocation overrides all other trust.
        """
        revoked = [
            e
            for e in self._entries
            if e.marker == REVOKE_MARKER
            and e.key is not None
            and self._hostname_matches(hostname, e)
        ]
        if not revoked:
            return False
        candidates = [key]
        info = _CertificateInfo.from_pkey(key)
        if info is not None:
            candidates.append(info.ca_key)
        for e in revoked:
            for candidate in candidates:
                if (
                    candidate is not None
                    and e.key.asbytes() == candidate.asbytes()
                ):
                    return True
        return False

    def _certificate_trusted(self, hostname, key):
        """
        True if ``key`` is a valid host certificate issued by a CA listed for
        a matching hostname in a ``@cert-authority`` line.
        """
        info = _CertificateInfo.from_pkey(key)
        if info is None:
            return False
        ca_key = info.ca_key
        cas = [
            e
            for e in self._lookup_entries(hostname)
            if e.marker == CA_MARKER and e.key is not None
        ]
        if not any(e.key.asbytes() == ca_key.asbytes() for e in cas):
            return False
        # A matching CA line vouches for the certificate only if the
        # certificate itself is valid for this host.
        return info.verify(hostname)

    def check(self, hostname, key):
        """
        Return True if the given key is associated with the given hostname
        in this dictionary.

        Host certificates are supported with OpenSSH semantics: if ``key``
        carries a certificate signed by a CA named in a matching
        ``@cert-authority`` line, and the certificate is a host certificate
        with a valid signature, current validity window, a matching principal,
        and no unsupported critical options, it is accepted.  A ``@revoked``
        line for the key (or for its CA) always rejects, even if a CA would
        otherwise vouch for it.

        :param str hostname: hostname (or IP) of the SSH server
        :param .PKey key: the key to check
        :return:
            ``True`` if the key is associated with the hostname; else ``False``
        """
        # Revocation takes priority over both pinned keys and CA trust.
        if self._is_revoked(hostname, key):
            return False
        if self._check_pinned(hostname, key):
            return True
        return self._certificate_trusted(hostname, key)

    def _check_pinned(self, hostname, key):
        """
        True if a plain (unmarked) entry for ``hostname`` pins ``key``.

        This is byte-for-byte public key comparison, as it has always been.
        Policy (CA/revoked) lines are ignored here.  Note this matches
        OpenSSH's behavior of falling back to the certified key's plain public
        key when no CA vouches for a presented certificate: possession of the
        pinned private key is still proven by the key exchange itself.
        """
        k = self.lookup(hostname)
        if k is None:
            return False
        host_key = k.get(key.get_name(), None)
        if host_key is None:
            return False
        return host_key.asbytes() == key.asbytes()

    def clear(self):
        """
        Remove all host keys from the dictionary.
        """
        self._entries = []

    def __iter__(self):
        for k in self.keys():
            yield k

    def __len__(self):
        return len(self.keys())

    def __getitem__(self, key):
        ret = self.lookup(key)
        if ret is None:
            raise KeyError(key)
        return ret

    def __delitem__(self, key):
        index = None
        for i, entry in enumerate(self._entries):
            # Only pinned (unmarked) entries are deletable this way; CA and
            # revoked lines are policy, not host key records.
            if entry.marker is None and self._hostname_matches(key, entry):
                index = i
                break
        if index is None:
            raise KeyError(key)
        self._entries.pop(index)

    def __setitem__(self, hostname, entry):
        # don't use this please.
        if len(entry) == 0:
            self._entries.append(HostKeyEntry([hostname], None))
            return
        for key_type in entry.keys():
            found = False
            for e in self._entries:
                if (
                    e.marker is None
                    and (hostname in e.hostnames)
                    and e.key.get_name() == key_type
                ):
                    # replace
                    e.key = entry[key_type]
                    found = True
            if not found:
                self._entries.append(HostKeyEntry([hostname], entry[key_type]))

    def keys(self):
        ret = []
        for e in self._entries:
            # Policy lines are not host key records.
            if e.marker is not None:
                continue
            for h in e.hostnames:
                if h not in ret:
                    ret.append(h)
        return ret

    def values(self):
        ret = []
        for k in self.keys():
            ret.append(self.lookup(k))
        return ret

    @staticmethod
    def hash_host(hostname, salt=None):
        """
        Return a "hashed" form of the hostname, as used by OpenSSH when storing
        hashed hostnames in the known_hosts file.

        :param str hostname: the hostname to hash
        :param str salt: optional salt to use when hashing
            (must be 20 bytes long)
        :return: the hashed hostname as a `str`
        """
        if salt is None:
            salt = os.urandom(sha1().digest_size)
        else:
            if salt.startswith("|1|"):
                salt = salt.split("|")[2]
            salt = decodebytes(b(salt))
        assert len(salt) == sha1().digest_size
        hmac = HMAC(salt, b(hostname), sha1).digest()
        hostkey = "|1|{}|{}".format(u(encodebytes(salt)), u(encodebytes(hmac)))
        return hostkey.replace("\n", "")


class InvalidHostKey(Exception):
    def __init__(self, line, exc):
        self.line = line
        self.exc = exc
        self.args = (line, exc)


class HostKeyEntry:
    """
    Representation of a line in an OpenSSH-style "known hosts" file.
    """

    def __init__(self, hostnames=None, key=None, marker=None):
        self.valid = (hostnames is not None) and (key is not None)
        self.hostnames = hostnames
        self.key = key
        # ``None`` for ordinary pinned host keys; otherwise one of the
        # OpenSSH known_hosts markers (``"cert-authority"`` / ``"revoked"``).
        self.marker = marker
        # Original text of a marked line, preserved verbatim so
        # `.HostKeys.save` can write it back unchanged.
        self._line = None

    @classmethod
    def from_line(cls, line, lineno=None):
        """
        Parses the given line of text to find the names for the host,
        the type of key, and the key data. The line is expected to be in the
        format used by the OpenSSH known_hosts file. Fields are separated by a
        single space or tab.

        OpenSSH marker lines (``@cert-authority`` and ``@revoked``) are also
        understood; the marker is retained on the returned entry (and thus by
        `.HostKeys.save`), without affecting how the key itself is parsed.

        Lines are expected to not have leading or trailing whitespace.
        We don't bother to check for comments or empty lines.  All of
        that should be taken care of before sending the line to us.

        :param str line: a line from an OpenSSH known_hosts file
        """
        log = get_logger("paramiko.hostkeys")
        marker, rest = cls._parse_marker(line, lineno)
        if rest is None:
            return None
        fields = re.split(" |\t", rest)
        if len(fields) < 3:
            # Bad number of fields
            msg = "Not enough fields found in known_hosts in line {} ({!r})"
            log.info(msg.format(lineno, line))
            return None
        fields = fields[:3]

        names, key_type, key = fields
        names = names.split(",")

        # Decide what kind of key we're looking at and create an object
        # to hold it accordingly.
        try:
            # TODO: this grew organically and doesn't seem /wrong/ per se (file
            # read -> unicode str -> bytes for base64 decode -> decoded bytes);
            # but in Python 3 forever land, can we simply use
            # `base64.b64decode(str-from-file)` here?
            key_bytes = decodebytes(b(key))
        except binascii.Error as e:
            raise InvalidHostKey(line, e)

        key_obj = cls._load_key(key_type, key_bytes, log)
        if key_obj is None:
            return None
        entry = cls(names, key_obj, marker=marker)
        if marker is not None:
            # Remember the exact source line so `save` can write it back
            # unchanged.
            entry._line = line
        return entry

    @staticmethod
    def _parse_marker(line, lineno=None):
        """
        Split off an optional leading known_hosts marker.

        Returns ``(marker, rest)``, where ``marker`` is ``None`` for ordinary
        lines.  Returns ``(None, None)`` for a malformed or unknown marker
        (OpenSSH's ``check_markers`` likewise rejects those, and only one
        marker may appear).
        """
        log = get_logger("paramiko.hostkeys")
        rest = line.strip()
        marker = None
        while rest.startswith("@"):
            # As in OpenSSH: the marker must be a non-empty token starting
            # immediately after the '@', terminated by whitespace.
            match = re.match(r"@([^ \t]+)[ \t]+", rest)
            if match is None or marker is not None:
                log.info(
                    "Invalid marker in known_hosts line {} ({!r})".format(
                        lineno, line
                    )
                )
                return None, None
            name = match.group(1)
            if name not in _MARKERS:
                log.info(
                    "Invalid marker in known_hosts line {} ({!r})".format(
                        lineno, line
                    )
                )
                return None, None
            marker = name
            rest = rest[match.end():]
        return marker, rest

    @staticmethod
    def _load_key(key_type, key_bytes, log):
        """
        Build a `.PKey` from known_hosts field data.

        Certificate key types (``<plain>-cert-v01@openssh.com``) are loaded
        against the underlying plain key class, which attaches the parsed
        certificate as ``.public_blob``.

        Returns ``None`` (and logs) for key types we don't understand.
        """
        candidates = [key_type]
        if key_type.endswith(_CERT_SUFFIX):
            candidates.append(key_type[: -len(_CERT_SUFFIX)])
        for candidate in candidates:
            try:
                return PKey.from_type_string(candidate, key_bytes)
            except UnknownKeyType:
                continue
        # TODO (backwards incompat): consider changing HostKeys API so this
        # just raises naturally and the exception is muted higher up in the
        # stack?
        log.info("Unable to handle key of type {}".format(key_type))
        return None

    def to_line(self):
        """
        Returns a string in OpenSSH known_hosts file format, or None if
        the object is not in a valid state.  A trailing newline is
        included.
        """
        if not self.valid:
            return None
        if self._line is not None:
            # Marked lines are policy, preserved exactly as they were read.
            return "{}\n".format(self._line)
        # Write the certificate blob (not the bare key) for cert-bearing
        # entries, so a loaded certificate round-trips as a certificate line.
        blob = getattr(self.key, "public_blob", None)
        if blob is not None:
            key_type = blob.key_type
            key_base64 = u(encodebytes(blob.key_blob)).replace("\n", "")
        else:
            key_type = self.key.get_name()
            key_base64 = self.key.get_base64()
        return "{} {} {}\n".format(
            ",".join(self.hostnames),
            key_type,
            key_base64,
        )

    def __repr__(self):
        return "<HostKeyEntry {!r}: {!r}>".format(self.hostnames, self.key)
