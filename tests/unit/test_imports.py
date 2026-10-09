def test_f_vra_imports():
    import f_vra
    from f_vra.cli.main import app
    from f_vra.localization.service import localize

    assert f_vra is not None
    assert app is not None
    assert localize is not None
