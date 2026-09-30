"""virusShare - identity, pairing and trusted-device storage.

Cryptographic primitives are taken from the ``cryptography`` package and the
standard library TLS stack only:

* long-term device identity  -> self-signed ECDSA P-256 X.509 certificate
* possession proof           -> ECDSA signature over a server nonce
* transport encryption       -> TLS 1.2+ (``ssl``) using the same key pair
* pairing code               -> SHA-256 over the sorted certificate fingerprints

Nothing here is custom cryptography.  Trust is "trust on first use, confirmed
out of band by comparing the pairing code on both screens" - the same model
used by SSH host keys and Syncthing device IDs.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import math
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from core.constants import get_identity_path, get_trust_store_path

SIGNATURE_CONTEXT_CLIENT = b"virusShare/client/v1"
SIGNATURE_CONTEXT_SERVER = b"virusShare/server/v1"
PAIRING_CONTEXT = b"virusShare/pairing/v1"

CERT_YEARS = 20

log = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised for any identity, signature or trust-store failure."""


# --------------------------------------------------------------------------- #
# Identity (self-signed certificate + private key)
# --------------------------------------------------------------------------- #

@dataclass
class Identity:
    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey
    path: Optional[Path] = None

    @property
    def cert_der(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.DER)

    @property
    def cert_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the certificate, lowercase hex."""
        return hashlib.sha256(self.cert_der).hexdigest()

    @property
    def fingerprint_short(self) -> str:
        return self.fingerprint[:16]

    @property
    def common_name(self) -> str:
        attrs = self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify_own(self, data: bytes, signature: bytes) -> bool:
        return verify_signature(self.cert_der, data, signature)


def fingerprint_cert(cert_der: bytes) -> str:
    """SHA-256 fingerprint of a DER-encoded certificate, lowercase hex."""
    if not cert_der:
        raise SecurityError("empty certificate")
    return hashlib.sha256(cert_der).hexdigest()


def generate_identity(path: Optional[Path] = None, common_name: str = "virusShare") -> Identity:
    """Create a new self-signed certificate and store it (key + cert) in one PEM file."""
    path = Path(path) if path else get_identity_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * CERT_YEARS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    material = cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(material)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows may refuse, best effort
        pass
    return Identity(certificate=cert, private_key=key, path=path)


def load_identity(path: Optional[Path] = None) -> Identity:
    """Load an existing identity, generating one on first run."""
    path = Path(path) if path else get_identity_path()
    if not path.exists():
        return generate_identity(path)
    try:
        material = path.read_bytes()
        cert_part, _, key_part = material.partition(b"-----END CERTIFICATE-----")
        cert_pem = cert_part + b"-----END CERTIFICATE-----\n"
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_part, password=None)
    except Exception as exc:
        raise SecurityError(f"cannot load identity from {path}: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SecurityError(f"unsupported identity key type in {path}")
    return Identity(certificate=cert, private_key=key, path=path)


def load_cert_der(cert_der: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(cert_der)
    except Exception as exc:
        raise SecurityError(f"invalid certificate: {exc}") from exc


def verify_signature(cert_der: bytes, data: bytes, signature: bytes) -> bool:
    """Verify an ECDSA-SHA256 signature made by the private key of ``cert_der``."""
    try:
        cert = load_cert_der(cert_der)
        pub = cert.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, SecurityError, ValueError, TypeError):
        return False


def client_challenge_data(server_nonce: bytes, client_nonce: bytes) -> bytes:
    return SIGNATURE_CONTEXT_CLIENT + b"|" + server_nonce + b"|" + client_nonce


def server_challenge_data(server_nonce: bytes) -> bytes:
    return SIGNATURE_CONTEXT_SERVER + b"|" + server_nonce


# --------------------------------------------------------------------------- #
# Pairing code
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class PairingCode:
    """Human-comparable code derived from two certificate fingerprints."""

    canonical: str  # 64 hex chars, order-independent
    full: str       # "ABCD-EF01-..." (first 16 hex chars, 4 groups of 4)
    short: str      # 6 decimal digits, convenience only

    @property
    def display(self) -> str:
        return f"{self.short}  ({self.full})"


def compute_pairing_code(fp_a: str, fp_b: str) -> PairingCode:
    """Derive a code from two certificate fingerprints.

    Fingerprints are sorted so both peers derive the same value.  The full
    code carries 64 bits of entropy (impractical to grind); the 6-digit short
    code is derived from that same 64-bit prefix, is a convenience display
    only and is never used for verification.
    """
    if not fp_a or not fp_b:
        raise SecurityError("both fingerprints are required for a pairing code")
    low, high = sorted([fp_a.lower(), fp_b.lower()])
    digest = hashlib.sha256(PAIRING_CONTEXT + low.encode() + b"|" + high.encode()).hexdigest()
    canonical = digest
    full = "-".join(digest[i : i + 4] for i in range(0, 16, 4)).upper()
    short = f"{int(digest[:16], 16) % 1_000_000:06d}"
    return PairingCode(canonical=canonical, full=full, short=short)


# --------------------------------------------------------------------------- #
# Trust store (persistent, device_id -> certificate fingerprint)
# --------------------------------------------------------------------------- #

class TrustStore:
    """Persists which peers have been explicitly paired with.

    Trust records the peer's *certificate fingerprint*.  device_id alone is
    self-asserted and is never treated as proof of identity - a connection is
    only trusted when the fingerprint presented on the wire matches the one
    stored here.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else get_trust_store_path()
        self._lock = threading.RLock()
        self._devices: Dict[str, dict] = {}
        self.load()

    # -- persistence ------------------------------------------------------- #

    def load(self) -> None:
        with self._lock:
            if not self.path.exists():
                self._devices = {}
                return
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                # H5: never start empty on top of a damaged file - the next
                # save() would wipe every paired device. Preserve the bytes
                # as a .corrupt-<timestamp> backup and say so in the log.
                stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
                backup = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
                try:
                    self.path.replace(backup)
                    log.error(
                        "trust store unreadable (%s); moved to %s, starting empty",
                        exc,
                        backup.name,
                    )
                except OSError:
                    log.exception(
                        "trust store unreadable (%s) and backup failed", exc
                    )
                self._devices = {}
                return
            devices = data.get("devices", {}) if isinstance(data, dict) else {}
            if not isinstance(devices, dict):
                devices = {}
            valid: Dict[str, dict] = {}
            dropped: List[str] = []
            for device_id, record in devices.items():
                if (
                    isinstance(device_id, str)
                    and isinstance(record, dict)
                    and isinstance(record.get("fingerprint"), str)
                    and isinstance(record.get("name"), str)
                ):
                    valid[device_id] = record
                else:
                    dropped.append(str(device_id))
            if dropped:
                # M34: malformed records must never reach the handshake, where
                # record.get(...).lower() would raise AttributeError.
                log.warning(
                    "dropped %d malformed trust record(s): %s",
                    len(dropped),
                    ", ".join(dropped),
                )
            self._devices = valid

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                {"version": 1, "devices": self._devices}, indent=2, sort_keys=True
            )
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())  # H5: a crash must not tear the store
            os.replace(tmp, self.path)

    # -- API --------------------------------------------------------------- #

    def is_trusted(self, device_id: str, fingerprint: Optional[str] = None) -> bool:
        """True when device_id is trusted; if a fingerprint is given, it must match."""
        with self._lock:
            record = self._devices.get(device_id)
            if not record:
                return False
            if fingerprint is None:
                return True
            return record.get("fingerprint", "").lower() == fingerprint.lower()

    def add(self, device_id: str, name: str, fingerprint: str) -> None:
        if not device_id or not fingerprint:
            raise SecurityError("device_id and fingerprint are required")
        with self._lock:
            self._devices[device_id] = {
                "name": name,
                "fingerprint": fingerprint.lower(),
                "added_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self.save()

    def remove(self, device_id: str) -> bool:
        with self._lock:
            existed = self._devices.pop(device_id, None) is not None
            if existed:
                self.save()
            return existed

    def get(self, device_id: str) -> Optional[dict]:
        with self._lock:
            record = self._devices.get(device_id)
            return dict(record) if record else None

    def list(self) -> List[dict]:
        with self._lock:
            return [
                {"device_id": device_id, **record}
                for device_id, record in sorted(self._devices.items())
            ]
