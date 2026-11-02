import sbom_validation


def test_package_is_importable() -> None:
    assert sbom_validation.__doc__ == "SBOM validation package."
