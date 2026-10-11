import shutil

import pytest

from app import create_app
from app.sample_data import generate


@pytest.fixture(scope="session")
def sample_pcap(tmp_path_factory):
    return generate(tmp_path_factory.mktemp("pcap") / "sample.pcap")


@pytest.fixture(scope="session")
def analysis(sample_pcap):
    from app.analyzer import analyze_file
    return analyze_file(sample_pcap)


@pytest.fixture
def client(tmp_path, sample_pcap):
    shutil.copy(sample_pcap, tmp_path / "network_analysis.pcapng")
    app = create_app({"DATA_DIR": tmp_path, "TESTING": True, "AUTO_SAMPLE": False})
    return app.test_client()
