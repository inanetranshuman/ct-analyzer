from ct_analyzer.cert.x509_features import validation_type_from_policy_oids


def test_validation_type_mapping_prefers_ev_then_ov_then_dv() -> None:
    assert validation_type_from_policy_oids(["2.23.140.1.2.1"]) == "DV"
    assert validation_type_from_policy_oids(["2.23.140.1.2.2"]) == "OV"
    assert validation_type_from_policy_oids(["2.23.140.1.1"]) == "EV"
    assert validation_type_from_policy_oids([]) == "Unknown"
