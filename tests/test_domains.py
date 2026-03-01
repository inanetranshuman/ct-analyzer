from ct_analyzer.cert.domains import get_registered_domain, tokenize_domain


def test_registered_domain_extraction() -> None:
    assert get_registered_domain("foo.bar.example.co.uk") == "example.co.uk"
    assert get_registered_domain("*.login.example.com") == "example.com"


def test_domain_tokenization() -> None:
    assert tokenize_domain("a.b.example.com") == [
        "a.b.example.com",
        "b.example.com",
        "example.com",
        "com",
    ]
