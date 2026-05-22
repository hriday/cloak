import pytest
from core.algorithm_loader import get_validators, get_codegen, AlgorithmNotFound


def test_unknown_algorithm_raises():
    with pytest.raises(AlgorithmNotFound):
        get_validators("does-not-exist")
