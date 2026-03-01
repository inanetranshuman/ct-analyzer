from ct_analyzer.cert.domains import get_registered_domain, idn_confusable_evidence, to_unicode_hostname, tokenize_domain


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


def test_unicode_hostname_conversion() -> None:
    assert to_unicode_hostname("xn--bcher-kva.example") == "bücher.example"
    assert to_unicode_hostname("*.xn--bcher-kva.example") == "*.bücher.example"


def test_idn_confusable_evidence_detects_ascii_lookalike() -> None:
    evidence = idn_confusable_evidence("www.xn--ellraboutique-dnb.com")
    assert evidence is not None
    assert evidence["unicode_hostname"] == "www.elløraboutique.com"
