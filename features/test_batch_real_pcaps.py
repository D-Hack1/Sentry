from features.batch_real_pcaps import process_all_pcaps


def test_process_all_pcaps_continues_after_failures(monkeypatch, tmp_path):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    nested_dir = input_dir / "nested"
    nested_dir.mkdir(parents=True)
    first = input_dir / "first.pcap"
    second = nested_dir / "second.pcap"
    first.touch()
    second.touch()

    def parse(pcap_path):
        if pcap_path.endswith("second.pcap"):
            raise ValueError("bad capture")
        return {"session_id": "first"}

    def process(_, ike_fields, destination):
        destination.mkdir(parents=True, exist_ok=True)
        (destination / f"{ike_fields['session_id']}.parquet").touch()
        return {"session_id": ike_fields["session_id"]}

    monkeypatch.setattr("features.batch_real_pcaps.parse_ike_pcap", parse)
    monkeypatch.setattr("features.batch_real_pcaps.process_pcap", process)

    count, successes, failures, parquet_count = process_all_pcaps(input_dir, output_dir)

    assert count == 2
    assert successes == 1
    assert len(failures) == 1
    assert parquet_count == 1
