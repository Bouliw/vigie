import vigie


def test_package_exposes_version():
    assert isinstance(vigie.__version__, str)
    assert vigie.__version__
