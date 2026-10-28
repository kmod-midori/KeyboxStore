"""Validation and metadata extraction for Android attestation keyboxes."""

from xml.etree import ElementTree as ET

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException


class InvalidKeybox(ValueError):
    pass


def only(parent: ET.Element, tag: str) -> ET.Element:
    elements = parent.findall(tag)
    if len(elements) != 1:
        raise InvalidKeybox(f"Expected exactly one {tag}")
    return elements[0]


def check_count(parent: ET.Element, tag: str, actual: int) -> None:
    try:
        count = int(only(parent, tag).text or "")
    except ValueError as exc:
        raise InvalidKeybox(f"Invalid {tag}") from exc
    if count != actual or actual < 1:
        raise InvalidKeybox(f"{tag} must match the non-empty element count")


def pem(element: ET.Element) -> bytes:
    if element.get("format") != "pem" or not element.text:
        raise InvalidKeybox("Keys and certificates must use PEM format")
    return element.text.strip().encode("utf-8")


def parse(data: bytes) -> tuple[ET.Element, list[dict]]:
    try:
        root = SafeET.fromstring(data, forbid_dtd=True)
    except (ET.ParseError, DefusedXmlException, ValueError) as exc:
        raise InvalidKeybox("Invalid or unsafe XML") from exc
    if root.tag != "AndroidAttestation":
        raise InvalidKeybox("Expected AndroidAttestation root")
    boxes = root.findall("Keybox")
    # Public templates can carry a stale count; actual elements define indexes.
    try:
        declared_count = int(only(root, "NumberOfKeyboxes").text or "")
    except ValueError as exc:
        raise InvalidKeybox("Invalid NumberOfKeyboxes") from exc
    if declared_count < 1 or not boxes:
        raise InvalidKeybox("At least one keybox is required")
    metadata = []
    for index, box in enumerate(boxes):
        if not box.get("DeviceID") or not box.findall("Key"):
            raise InvalidKeybox(
                f"Keybox {index} requires DeviceID and at least one Key"
            )
        keys = []
        algorithms = set()
        for key in box.findall("Key"):
            algorithm = key.get("algorithm")
            if algorithm not in {"rsa", "ecdsa"} or algorithm in algorithms:
                raise InvalidKeybox(
                    f"Keybox {index}: unsupported or duplicate algorithm"
                )
            algorithms.add(algorithm)
            chain = only(key, "CertificateChain")
            certificates = chain.findall("Certificate")
            check_count(chain, "NumberOfCertificates", len(certificates))
            try:
                parsed = []
                for certificate in certificates:
                    loaded = x509.load_pem_x509_certificates(pem(certificate))
                    if len(loaded) != 1:
                        raise InvalidKeybox(
                            "Each Certificate must contain one PEM certificate"
                        )
                    parsed.append(loaded[0])
                leaf = parsed[0]
                private = serialization.load_pem_private_key(
                    pem(only(key, "PrivateKey")), password=None
                )
                expected = (
                    rsa.RSAPrivateKey
                    if algorithm == "rsa"
                    else ec.EllipticCurvePrivateKey
                )
                if not isinstance(private, expected):
                    raise InvalidKeybox(
                        "Private key does not match its declared algorithm"
                    )
                public = leaf.public_key()
                encoding = serialization.Encoding.DER
                fmt = serialization.PublicFormat.SubjectPublicKeyInfo
                if private.public_key().public_bytes(
                    encoding, fmt
                ) != public.public_bytes(encoding, fmt):
                    raise InvalidKeybox(
                        "Private key does not match the first certificate"
                    )
                keys.append(
                    {
                        "algorithm": algorithm,
                        "certificate_count": len(parsed),
                        "certificate_expirations": [
                            cert.not_valid_after_utc.isoformat() for cert in parsed
                        ],
                        "leaf": {
                            "subject": leaf.subject.rfc4514_string(),
                            "issuer": leaf.issuer.rfc4514_string(),
                            "serial_number": str(leaf.serial_number),
                            "not_valid_before": leaf.not_valid_before_utc.isoformat(),
                            "not_valid_after": leaf.not_valid_after_utc.isoformat(),
                            "sha256_fingerprint": leaf.fingerprint(
                                hashes.SHA256()
                            ).hex(),
                            "signature_algorithm_oid": leaf.signature_algorithm_oid.dotted_string,
                            "public_key_bits": public.key_size,
                        },
                    }
                )
            except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
                # Never include parser exception text that could contain key material.
                raise InvalidKeybox(
                    f"Keybox {index}: invalid key or certificate chain"
                ) from exc
        metadata.append(
            {"index": index, "device_id": box.get("DeviceID"), "keys": keys}
        )
    return root, metadata


def export(root: ET.Element, indexes: list[int]) -> bytes:
    result = ET.Element("AndroidAttestation")
    ET.SubElement(result, "NumberOfKeyboxes").text = str(len(indexes))
    boxes = root.findall("Keybox")
    result.extend(boxes[index] for index in indexes)
    return ET.tostring(result, encoding="utf-8", xml_declaration=True)
