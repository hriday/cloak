import pytest
from core.algorithm_loader import get_validators, get_codegen, AlgorithmNotFound


def test_get_codegen_for_rsa():
    mod = get_codegen("rsa")
    assert mod.ping() == "rsa-codegen-ok"


def test_unknown_algorithm_raises():
    with pytest.raises(AlgorithmNotFound):
        get_validators("does-not-exist")
