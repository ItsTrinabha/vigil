"""`python -m vigil` - run the Vigil server."""
from __future__ import annotations

import datetime
import ipaddress
import logging
import socket

import uvicorn

from .config import get_settings


def ensure_self_signed(cert_path, key_path, hostnames: list[str]) -> None:
    """Create a self-signed certificate on first start so traffic is encrypted by default."""
    if cert_path.exists() and key_path.exists():
        return
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0]),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vigil SIEM (self-signed)")])
    sans: list[x509.GeneralName] = []
    for h in hostnames:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            sans.append(x509.DNSName(h))
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    s = get_settings()
    ssl = {}
    if s.tls:
        cert = s.tls_cert or str(s.data_dir / "tls" / "vigil.crt")
        key = s.tls_key or str(s.data_dir / "tls" / "vigil.key")
        if not s.tls_cert:
            from pathlib import Path
            (s.data_dir / "tls").mkdir(exist_ok=True)
            names = ["vigil-server", "localhost", "127.0.0.1", socket.gethostname()]
            ensure_self_signed(Path(cert), Path(key), names)
        ssl = {"ssl_certfile": cert, "ssl_keyfile": key}
    from .main import create_app
    uvicorn.run(create_app(s), host=s.host, port=s.port, log_level="info", proxy_headers=False,
                server_header=False, **ssl)


if __name__ == "__main__":
    main()
