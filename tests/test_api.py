from datetime import UTC, datetime, timedelta
from xml.etree import ElementTree as ET

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from keyboxstore.app import create_app


@pytest.fixture(scope="module")
def document():
    root = ET.Element("AndroidAttestation")
    ET.SubElement(root, "NumberOfKeyboxes").text = "2"
    for index in range(2):
        box = ET.SubElement(root, "Keybox", DeviceID=f"device-{index}")
        for algorithm in ("rsa", "ecdsa"):
            private = (
                rsa.generate_private_key(public_exponent=65537, key_size=2048)
                if algorithm == "rsa"
                else ec.generate_private_key(ec.SECP256R1())
            )
            name = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, f"{algorithm}-{index}")]
            )
            now = datetime.now(UTC)
            certificate = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(private.public_key())
                .serial_number(index + 100)
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=30))
                .sign(private, hashes.SHA256())
            )
            key = ET.SubElement(box, "Key", algorithm=algorithm)
            ET.SubElement(key, "PrivateKey", format="pem").text = private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()
            chain = ET.SubElement(key, "CertificateChain")
            ET.SubElement(chain, "NumberOfCertificates").text = "1"
            ET.SubElement(
                chain, "Certificate", format="pem"
            ).text = certificate.public_bytes(serialization.Encoding.PEM).decode()
    return ET.tostring(root)


def upload(client, data):
    return client.post(
        "/keyboxes", files={"file": ("keybox.xml", data, "application/xml")}
    )


def test_round_trip_and_restart(tmp_path, document):
    path = tmp_path / "keybox.xml"
    with TestClient(create_app(path)) as client:
        assert client.get("/keyboxes").status_code == 404
        response = upload(client, document)
        assert response.status_code == 201
        assert response.json()["count"] == 2
        assert path.read_bytes() == document
        assert path.stat().st_mode & 0o777 == 0o600
        assert "PRIVATE KEY" not in response.text
        metadata = client.get("/keyboxes/1").json()
        assert metadata["device_id"] == "device-1"
        assert metadata["keys"][0]["leaf"]["serial_number"] == "101"
        assert metadata["keys"][1]["leaf"]["subject"] == "CN=ecdsa-1"
        exported = client.get("/keyboxes/1/export")
        assert exported.status_code == 200
        assert exported.headers["cache-control"] == "no-store"
        root = ET.fromstring(exported.content)
        assert root.findtext("NumberOfKeyboxes") == "1"
        assert len(root.findall("Keybox")) == 1
        original = ET.fromstring(document).findall("Keybox")[1]
        assert ET.tostring(root.find("Keybox")) == ET.tostring(original)
    with TestClient(create_app(path)) as restarted:
        assert restarted.get("/keyboxes").json()["count"] == 2
        assert upload(restarted, exported.content).status_code == 201
        assert restarted.get("/keyboxes/0").json()["device_id"] == "device-1"
        assert restarted.get("/keyboxes/1").status_code == 404


@pytest.mark.parametrize(
    "invalid",
    [
        b"",
        b"<broken",
        b"<Wrong/>",
        b'<!DOCTYPE x [<!ENTITY a "test">]><AndroidAttestation>&a;</AndroidAttestation>',
    ],
)
def test_invalid_upload_preserves_existing(tmp_path, document, invalid):
    path = tmp_path / "keybox.xml"
    with TestClient(create_app(path)) as client:
        assert upload(client, document).status_code == 201
        assert upload(client, invalid).status_code == 422
        assert path.read_bytes() == document


def test_bad_counts_certificates_and_key_mismatch(tmp_path, document):
    with TestClient(create_app(tmp_path / "keybox.xml")) as client:
        for tag in (
            "NumberOfKeyboxes",
            "NumberOfCertificates",
            "Certificate",
            "PrivateKey",
        ):
            root = ET.fromstring(document)
            root.find(f".//{tag}").text = "invalid"
            assert upload(client, ET.tostring(root)).status_code == 422
        root = ET.fromstring(document)
        keys = root.findall(".//Key[@algorithm='rsa']/PrivateKey")
        keys[0].text = keys[1].text
        assert upload(client, ET.tostring(root)).status_code == 422
        assert client.get("/keyboxes").status_code == 404


def test_limits_and_missing_indexes(tmp_path, document):
    with TestClient(
        create_app(tmp_path / "keybox.xml", max_upload_bytes=len(document))
    ) as client:
        assert upload(client, document + b" ").status_code == 413
        assert upload(client, document).status_code == 201
        for endpoint in ("/keyboxes/2", "/keyboxes/2/export"):
            assert client.get(endpoint).status_code == 404
        assert client.get("/keyboxes/-1/export").status_code == 422
        assert client.get("/keyboxes/nope").status_code == 422
        assert client.post("/keyboxes").status_code == 422


def test_public_keybox_fixture(tmp_path):
    from pathlib import Path

    # The upstream template declares two keyboxes but contains only one.
    fixture = Path(__file__).parent / "fixtures" / "keybox.xml"
    document = fixture.read_bytes()
    with TestClient(create_app(tmp_path / "keybox.xml")) as client:
        result = upload(client, document)
        assert result.status_code == 201, result.text
        metadata = result.json()
        assert metadata["count"] == 1
        assert metadata["keyboxes"][0]["device_id"] == "sw"
        keys = metadata["keyboxes"][0]["keys"]
        assert {key["algorithm"] for key in keys} == {"rsa", "ecdsa"}
        for key in keys:
            assert key["certificate_count"] == 2
            expected_cn = (
                "Android Keystore Software Attestation Intermediate"
                if key["algorithm"] == "ecdsa"
                else "Android Software Attestation Key"
            )
            assert key["leaf"]["subject"].startswith(f"CN={expected_cn},")
        exported = client.get("/keyboxes/0/export")
        assert exported.status_code == 200
        root = ET.fromstring(exported.content)
        assert root.findtext("NumberOfKeyboxes") == "1"
        assert ET.tostring(root.find("Keybox")) == ET.tostring(
            ET.fromstring(document).find("Keybox")
        )
        assert upload(client, exported.content).json() == metadata
        assert client.get("/keyboxes/1/export").status_code == 404


@pytest.mark.parametrize("result", [200, 503, "timeout"])
def test_ntfy_upload(tmp_path, document, monkeypatch, caplog, result):
    import httpx

    from keyboxstore import notifications

    calls = []
    path = tmp_path / "keybox.xml"

    def handler(request):
        calls.append(request)
        assert path.read_bytes() == document
        assert request.method == "POST"
        assert request.headers["Authorization"] == "Bearer test-token"
        assert request.headers["Title"] == "KeyboxStore updated"
        message = request.content.decode()
        assert message.startswith("Keybox file replaced successfully (2 keyboxes).\n")
        assert "First keybox certificate validity (UTC):" in message
        first_box = ET.fromstring(document).find("Keybox")
        for key in first_box.findall("Key"):
            certificate = x509.load_pem_x509_certificate(
                key.findtext("CertificateChain/Certificate").encode()
            )
            assert (
                f"{key.get('algorithm').upper()}: "
                f"{certificate.not_valid_before_utc.isoformat()} to "
                f"{certificate.not_valid_after_utc.isoformat()}"
            ) in message
        assert "PRIVATE KEY" not in message
        if result == "timeout":
            raise httpx.ReadTimeout("sensitive URL", request=request)
        return httpx.Response(result)

    original_client = httpx.Client

    def mock_client(**kwargs):
        assert kwargs["timeout"] == 5
        assert kwargs["follow_redirects"] is False
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(notifications.httpx, "Client", mock_client)
    monkeypatch.setenv("NTFY_URL", "https://ntfy.example/private-topic")
    monkeypatch.setenv("NTFY_TOKEN", "test-token")
    with TestClient(create_app(path)) as client:
        assert upload(client, b"invalid").status_code == 422
        assert calls == []
        assert upload(client, document).status_code == 201
        assert len(calls) == 1
        assert client.get("/keyboxes").status_code == 200
        assert client.get("/keyboxes/0/export").status_code == 200
        assert len(calls) == 1
    if result != 200:
        assert "notification failed" in caplog.text
        assert "private-topic" not in caplog.text
        assert "test-token" not in caplog.text


def test_ntfy_disabled(tmp_path, document, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Notification should be disabled")

    monkeypatch.setattr("keyboxstore.app.notify_upload", unexpected)
    with TestClient(create_app(tmp_path / "keybox.xml")) as client:
        assert upload(client, document).status_code == 201
