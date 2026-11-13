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

"""
Some unit tests for HostKeys.
"""

from base64 import decodebytes, encodebytes
from binascii import hexlify
import os
import time
import unittest

import paramiko
from paramiko.message import Message

from ._util import _support


test_hosts_file = """\
secure.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
broken.example.com ssh-rsa AAAA
happy.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz\
dHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv9\
T9iRZjQzvJd5s+kBAZtpk=
"""

test_hosts_file_tabs = """\
secure.example.com\tssh-rsa\tAAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
happy.example.com\tssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com\tssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com\tecdsa-sha2-nistp256\tAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbml\
zdHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv\
9T9iRZjQzvJd5s+kBAZtpk=
"""

keyblob = b"""\
AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3GQ/Fc7SX6gkpXkwcZryoi4k\
NFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgK\
oc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M="""


class HostKeysTest(unittest.TestCase):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file)

    def tearDown(self):
        os.unlink("hostfile.temp")

    def test_load(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        assert len(hostdict) == 4
        self.assertEqual(1, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)

    def test_add(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        hh = "|1|BMsIC6cUIP2zBuXR3t2LRcJYjzM=|hpkJMysjTk/+zzUUzxQEa2ieq6c="
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        hostdict.add(hh, "ssh-rsa", key)
        assert len(hostdict) == 5
        x = hostdict["foo.example.com"]
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        self.assertTrue(hostdict.check("foo.example.com", key))

    def test_dict(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        x = hostdict.get("secure.example.com", None)
        self.assertTrue(x is not None)
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)
        assert list(hostdict) == hostdict.keys()
        assert len(list(hostdict)) == len(hostdict.keys()) == 4

    def test_dict_set(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        key_ed25519 = paramiko.Ed25519Key.from_private_key_file(
            _support("ed25519.key")
        )
        hostdict["secure.example.com"] = {
            "ssh-rsa": key,
            "ssh-ed25519": key_ed25519,
        }
        hostdict["fake.example.com"] = {}
        hostdict["fake.example.com"]["ssh-rsa"] = key

        assert len(hostdict) == 5
        self.assertEqual(2, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        self.assertEqual(1, len(list(hostdict.values())[2]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-ed25519"].get_fingerprint()
        ).upper()
        self.assertEqual(b"B3D522AAF9755EE8CD0EEA02B929A280", fp)

    def test_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        hostdict[target]  # will KeyError if not present
        del hostdict[target]
        try:
            hostdict[target]
        except KeyError:
            pass  # Good
        else:
            assert False, "Entry was not deleted from HostKeys on delitem!"

    def test_entry_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        entry = hostdict[target]
        key_type_list = [key_type for key_type in entry]
        for key_type in key_type_list:
            del entry[key_type]

        # will KeyError if not present
        for key_type in key_type_list:
            try:
                del entry[key_type]
            except KeyError:
                pass  # Good
            else:
                assert False, "Key was not deleted from Entry on delitem!"


class HostKeysTabsTest(HostKeysTest):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file_tabs)


# --- Offline certificate fixtures -------------------------------------------
#
# Everything below is built from the key material in tests/_support: we only
# need public halves inside the certificate and a CA private half to sign it.

CERT_SUFFIX = "-cert-v01@openssh.com"
CERT_TYPE_USER = 1
CERT_TYPE_HOST = 2


def _ca_private_key():
    """Private form of the ed25519 CA key kept in tests/_support."""
    return paramiko.Ed25519Key.from_private_key_file(_support("ed25519.key"))


def _ca_key():
    """Public form of the ed25519 CA key kept in tests/_support."""
    return paramiko.Ed25519Key(data=_ca_private_key().asbytes())


def _subject_key():
    """A host key unrelated to the CA, as a real server's key would be."""
    return paramiko.ECDSAKey.from_private_key_file(_support("ecdsa-256.key"))


def _build_certificate(
    subject,
    ca_private,
    cert_type=CERT_TYPE_HOST,
    principals=("host.example.com",),
    valid_after=0,
    valid_before=2**63,
    critical=(),
    extensions=(),
    critical_raw=None,
):
    """
    Build an OpenSSH ``*-cert-v01@openssh.com`` certificate offline.

    ``subject`` is a `.PKey` whose public half becomes the certificate
    subject; ``ca_private`` signs it.  Returns a `.PKey` with the certificate
    attached as ``.public_blob``, exactly as loading it from known_hosts would.
    """
    cert_type_string = subject.get_name() + CERT_SUFFIX
    m = Message()
    m.add_string(cert_type_string)
    m.add_string(os.urandom(32))  # nonce
    # Subject public key fields: the plain blob minus its type string.
    plain = Message(subject.asbytes())
    plain.get_text()
    m.add_bytes(plain.get_remainder())
    m.add_int64(1)  # serial
    m.add_int(cert_type)
    m.add_string("host cert")  # key id
    principals_blob = Message()
    for principal in principals:
        principals_blob.add_string(principal)
    m.add_string(principals_blob.asbytes())
    m.add_int64(valid_after)
    m.add_int64(valid_before)
    critical_blob = Message()
    for name, value in critical:
        critical_blob.add_string(name)
        critical_blob.add_string(value)
    if critical_raw is None:
        m.add_string(critical_blob.asbytes())
    else:
        m.add_string(critical_raw)
    extensions_blob = Message()
    for name, value in extensions:
        extensions_blob.add_string(name)
        extensions_blob.add_string(value)
    m.add_string(extensions_blob.asbytes())
    m.add_string(b"")  # reserved
    m.add_string(ca_private.asbytes())  # signing (CA) key blob
    # OpenSSH signs everything up to (not including) the signature.
    signed = m.asbytes()
    m.add_string(ca_private.sign_ssh_data(signed).asbytes())
    return paramiko.PKey.from_type_string(cert_type_string, m.asbytes())


def _ca_line(hosts, marker="cert-authority", ca=None):
    ca = _ca_key() if ca is None else ca
    return "@{} {} {} {}\n".format(
        marker, hosts, ca.get_name(), ca.get_base64()
    )


def _pinned_line(hosts, key):
    return "{} {} {}\n".format(hosts, key.get_name(), key.get_base64())


def _cert_line(hosts, cert):
    blob = cert.public_blob
    encoded = encodebytes(blob.key_blob).decode("ascii").replace("\n", "")
    return "{} {} {}\n".format(hosts, blob.key_type, encoded)


def _write_known_hosts(tmp_path, text):
    path = tmp_path / "known_hosts"
    path.write_text(text)
    return str(path)


class TestHostKeysMarkers:
    """``@cert-authority`` / ``@revoked`` lines load, and save verbatim."""

    def test_marker_lines_load_without_raising(self, tmp_path):
        text = (
            _ca_line("*.example.com")
            + _ca_line("[revoked.example.com]:2222", marker="revoked")
            + _pinned_line("pinned.example.com", _subject_key())
        )
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        # Marked lines are policy, not pinned records: invisible as host keys.
        assert keys.keys() == ["pinned.example.com"]
        assert len(keys) == 1

    def test_marker_lines_round_trip_verbatim(self, tmp_path):
        text = (
            _ca_line("*.example.com")
            + _ca_line("bad.example.com,!good.example.com", marker="revoked")
        )
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        out = str(tmp_path / "saved")
        keys.save(out)
        assert open(out).read() == text

    def test_invalid_marker_lines_are_skipped(self, tmp_path):
        good = _subject_key()
        keytype, base64 = good.get_name(), good.get_base64()
        text = (
            "@bogus *.example.com {} {}\n".format(keytype, base64)
            + "@cert-authority @revoked *.example.com {} {}\n".format(
                keytype, base64
            )
            + "@ *.example.com {} {}\n".format(keytype, base64)
            + "@cert-authority*.example.com {} {}\n".format(keytype, base64)
        )
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        assert keys._entries == []


class TestHostCertificate:
    """Host certificate validation, OpenSSH style."""

    def _keys(self, tmp_path, ca_hosts="*.example.com"):
        text = _ca_line(ca_hosts)
        return paramiko.HostKeys(_write_known_hosts(tmp_path, text))

    def test_valid_certificate_is_trusted(self, tmp_path):
        cert = _build_certificate(_subject_key(), _ca_private_key())
        keys = self._keys(tmp_path)
        assert keys.check("host.example.com", cert)
        # Works for the ubiquitous "[host]:port" spelling too.
        assert keys.check("[host.example.com]:22", cert)

    def test_valid_certificate_loaded_from_known_hosts_is_trusted(
        self, tmp_path
    ):
        cert = _build_certificate(_subject_key(), _ca_private_key())
        text = _ca_line("*.example.com") + _cert_line(
            "host.example.com", cert
        )
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        # Pull back the key object that loading the cert line produced.  Keys
        # are indexed by their plain name, as for ordinary public keys.
        loaded = keys["host.example.com"][cert.get_name()]
        assert loaded.public_blob.key_type == cert.public_blob.key_type
        assert loaded.public_blob.key_blob == cert.public_blob.key_blob
        assert keys.check("host.example.com", loaded)

    def test_certificate_entry_round_trips_as_certificate(self, tmp_path):
        cert = _build_certificate(_subject_key(), _ca_private_key())
        text = _cert_line("host.example.com", cert)
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        out = str(tmp_path / "saved")
        keys.save(out)
        assert open(out).read() == text
        # And it still validates after the round trip.
        text2 = _ca_line("*.example.com") + open(out).read()
        keys2 = paramiko.HostKeys(_write_known_hosts(tmp_path, text2))
        assert keys2.check("host.example.com", cert)

    def test_wildcard_and_negation_host_patterns(self, tmp_path):
        text = _ca_line("*.example.com,!secret.example.com")
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        public = _build_certificate(
            _subject_key(), _ca_private_key(),
            principals=("public.example.com",),
        )
        secret = _build_certificate(
            _subject_key(), _ca_private_key(),
            principals=("secret.example.com",),
        )
        assert keys.check("public.example.com", public)
        # Negated pattern vetoes an otherwise-matching wildcard.
        assert not keys.check("secret.example.com", secret)

    def test_question_mark_wildcard(self, tmp_path):
        keys = paramiko.HostKeys(
            _write_known_hosts(tmp_path, _ca_line("h?st.example.com"))
        )
        assert keys.check(
            "host.example.com",
            _build_certificate(_subject_key(), _ca_private_key()),
        )
        assert not keys.check(
            "hoost.example.com",
            _build_certificate(
                _subject_key(), _ca_private_key(),
                principals=("hoost.example.com",),
            ),
        )

    def test_ca_line_for_other_host_does_not_apply(self, tmp_path):
        cert = _build_certificate(_subject_key(), _ca_private_key())
        assert not self._keys(tmp_path, ca_hosts="other.example.com").check(
            "host.example.com", cert
        )

    def test_non_host_certificate_rejected(self, tmp_path):
        cert = _build_certificate(
            _subject_key(), _ca_private_key(), cert_type=CERT_TYPE_USER
        )
        assert not self._keys(tmp_path).check("host.example.com", cert)

    def test_expired_certificate_rejected(self, tmp_path):
        cert = _build_certificate(
            _subject_key(), _ca_private_key(),
            valid_before=int(time.time()) - 60,
        )
        assert not self._keys(tmp_path).check("host.example.com", cert)

    def test_not_yet_valid_certificate_rejected(self, tmp_path):
        cert = _build_certificate(
            _subject_key(), _ca_private_key(),
            valid_after=int(time.time()) + 3600,
        )
        assert not self._keys(tmp_path).check("host.example.com", cert)

    def test_certificate_without_matching_principal_rejected(self, tmp_path):
        cert = _build_certificate(
            _subject_key(), _ca_private_key(),
            principals=("other.example.com",),
        )
        assert not self._keys(tmp_path).check("host.example.com", cert)

    def test_certificate_with_no_principals_rejected(self, tmp_path):
        cert = _build_certificate(
            _subject_key(), _ca_private_key(), principals=()
        )
        assert not self._keys(tmp_path).check("host.example.com", cert)

    def test_unknown_critical_option_rejected(self, tmp_path):
        cert = _build_certificate(
            _subject_key(), _ca_private_key(),
            critical=(("unknown-critical-option", b"data"),),
        )
        assert not self._keys(tmp_path).check("host.example.com", cert)

    def test_signed_by_untrusted_ca_rejected(self, tmp_path):
        other_ca = paramiko.RSAKey.from_private_key_file(_support("rsa.key"))
        cert = _build_certificate(_subject_key(), other_ca)
        assert not self._keys(tmp_path).check("host.example.com", cert)

    def test_tampered_signature_rejected(self, tmp_path):
        cert = _build_certificate(_subject_key(), _ca_private_key())
        blob = cert.public_blob.key_blob
        forged = paramiko.PKey.from_type_string(
            cert.public_blob.key_type, blob[:-8] + b"forged!!"
        )
        assert not self._keys(tmp_path).check("host.example.com", forged)

    def test_truncated_certificate_rejected(self, tmp_path):
        cert = _build_certificate(_subject_key(), _ca_private_key())
        blob = cert.public_blob.key_blob
        truncated = paramiko.PKey.from_type_string(
            cert.public_blob.key_type, blob[: len(blob) // 2]
        )
        assert not self._keys(tmp_path).check("host.example.com", truncated)

    def test_malformed_critical_section_rejected(self, tmp_path):
        # A critical-options section whose inner lengths overrun the section
        # must render the certificate unparseable, not merely "empty".
        cert = _build_certificate(
            _subject_key(), _ca_private_key(),
            critical_raw=b"\x00\x00\x00\x09abc",
        )
        assert not self._keys(tmp_path).check("host.example.com", cert)

    def test_revoked_ca_beats_cert_authority(self, tmp_path):
        ca = _ca_key()
        cert = _build_certificate(_subject_key(), _ca_private_key())
        text = _ca_line("*.example.com") + _ca_line(
            "*.example.com", marker="revoked", ca=ca
        )
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        assert not keys.check("host.example.com", cert)

    def test_revoked_subject_key_beats_cert_authority(self, tmp_path):
        subject = _subject_key()
        cert = _build_certificate(subject, _ca_private_key())
        text = _ca_line("*.example.com") + _ca_line(
            "*.example.com", marker="revoked", ca=subject
        )
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        assert not keys.check("host.example.com", cert)

    def test_revoked_without_port_also_covers_port_qualified_name(
        self, tmp_path
    ):
        ca = _ca_key()
        text = _ca_line("*.example.com") + _ca_line(
            "*.example.com", marker="revoked", ca=ca
        )
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        cert = _build_certificate(_subject_key(), _ca_private_key())
        assert not keys.check("[host.example.com]:2222", cert)

    def test_revoked_beats_pinned_plain_key(self, tmp_path):
        key = _subject_key()
        # A pinned key that is also explicitly revoked must be rejected.
        text = _pinned_line("host.example.com", key) + _ca_line(
            "host.example.com", marker="revoked", ca=key
        )
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        assert not keys.check("host.example.com", key)

    def test_hashed_ca_line_matches(self, tmp_path):
        cert = _build_certificate(_subject_key(), _ca_private_key())
        hashed = paramiko.HostKeys.hash_host("host.example.com")
        keys = paramiko.HostKeys(
            _write_known_hosts(tmp_path, _ca_line(hashed))
        )
        assert keys.check("host.example.com", cert)

    def test_ca_line_hostname_matching_is_case_insensitive(self, tmp_path):
        cert = _build_certificate(_subject_key(), _ca_private_key())
        keys = paramiko.HostKeys(
            _write_known_hosts(tmp_path, _ca_line("*.EXAMPLE.COM"))
        )
        assert keys.check("host.example.com", cert)

    def test_plain_keys_and_pinning_unaffected(self, tmp_path):
        key = _subject_key()
        text = _ca_line("*.example.com") + _pinned_line(
            "host.example.com", key
        )
        keys = paramiko.HostKeys(_write_known_hosts(tmp_path, text))
        assert keys.check("host.example.com", key)
        # A different key is still rejected even though a CA line would apply
        # to a certificate for this host.
        assert not keys.check(
            "host.example.com", paramiko.RSAKey.from_private_key_file(
                _support("rsa.key")
            )
        )

    def test_pinned_certificate_still_matches(self, tmp_path):
        cert = _build_certificate(_subject_key(), _ca_private_key())
        # An exact certificate entry pins the presented certificate.
        keys = paramiko.HostKeys(
            _write_known_hosts(tmp_path, _cert_line("host.example.com", cert))
        )
        assert keys.check("host.example.com", keys["host.example.com"][
            cert.get_name()
        ])

    def test_plain_pin_matches_certificate_subject_key(self, tmp_path):
        # OpenSSH falls back to the plain key when no CA vouches for a
        # presented certificate, so a pinned plain entry for the key still
        # matches that key's certificate - unchanged pinning behavior.
        cert = _build_certificate(
            _subject_key(), _ca_private_key(),
            principals=("other.example.com",),
        )
        subject = paramiko.PKey.from_type_string(
            cert.get_name(), cert.asbytes()
        )
        keys = paramiko.HostKeys(
            _write_known_hosts(
                tmp_path, _pinned_line("host.example.com", subject)
            )
        )
        assert keys.check("host.example.com", cert)
        assert keys.check("host.example.com", subject)

    def test_hashed_hostname_still_matches(self, tmp_path):
        key = _subject_key()
        hashed = paramiko.HostKeys.hash_host("host.example.com")
        keys = paramiko.HostKeys(
            _write_known_hosts(
                tmp_path, _pinned_line(hashed, key)
            )
        )
        assert keys.check("host.example.com", key)
        assert not keys.check("other.example.com", key)
