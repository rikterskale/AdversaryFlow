from scripts.documentation_provenance import validate_register


def test_documentation_provenance_register_is_complete():
    assert validate_register() == []
