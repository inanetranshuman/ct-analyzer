from ct_analyzer.cert.domains import highest_label_entropy


def test_entropy_heuristic_distinguishes_randomish_labels() -> None:
    assert highest_label_entropy("aaaaaa.example.com") < highest_label_entropy("a9x3kq7z.example.com")
