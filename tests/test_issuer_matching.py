from ct_analyzer.cert.parse import issuer_matches
from ct_analyzer.config import IssuerMatchingSettings


def test_issuer_dn_matching() -> None:
    settings = IssuerMatchingSettings(match_mode="issuer_dn", issuer_substrings=["Go Daddy"])
    assert issuer_matches("CN=Go Daddy Secure CA,O=Go Daddy", None, settings)
    assert not issuer_matches("CN=Other CA,O=Other", None, settings)


def test_hybrid_matching_uses_spki_hash_when_configured() -> None:
    settings = IssuerMatchingSettings(
        match_mode="hybrid",
        issuer_substrings=["Starfield"],
        issuer_spki_hashes=["abc123"],
    )
    assert issuer_matches("CN=Other", "abc123", settings)
