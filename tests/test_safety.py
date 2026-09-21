import pytest

from src.utils.target_validator import (
    TargetKind,
    TargetValidationError,
    validate_resolved_address,
    validate_target,
)


def test_authorized_public_domain_is_accepted():
    target = validate_target("example.com", authorized=True)

    assert target.value == "example.com"
    assert target.kind == TargetKind.DOMAIN


def test_authorized_public_ip_is_accepted():
    target = validate_target("1.1.1.1", authorized=True)

    assert target.value == "1.1.1.1"
    assert target.kind == TargetKind.IP_ADDRESS


def test_target_requires_explicit_authorization():
    with pytest.raises(TargetValidationError, match="explicit authorization"):
        validate_target("example.com", authorized=False)


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "192.168.1.10",
        "10.0.0.1",
        "172.16.0.1",
        "::1",
    ],
)
def test_non_public_ip_addresses_are_rejected(target):
    with pytest.raises(TargetValidationError, match="Non-public"):
        validate_target(target, authorized=True)


@pytest.mark.parametrize(
    "target",
    [
        "localhost",
        "app.local",
        "server.internal",
        "device.lan",
    ],
)
def test_local_or_internal_domains_are_rejected(target):
    with pytest.raises(TargetValidationError):
        validate_target(target, authorized=True)


def test_non_public_resolved_address_is_rejected():
    with pytest.raises(TargetValidationError, match="Non-public"):
        validate_resolved_address("192.168.1.10")