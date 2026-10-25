import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import plot_training_metrics as ptm  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "examples" / "training_logs"


def test_load_json_sample():
    points, meta = ptm.load_log(SAMPLES / "sample_run.json")
    assert points[0][0] == 0
    assert meta == {
        "model_name": "adexa-repair-v1",
        "dataset_version": "2026.05",
        "checkpoint": "checkpoint-1000",
    }
    assert any(v is not None for _, _, v in points)


def test_load_csv_sample_matches_json():
    csv_points, csv_meta = ptm.load_log(SAMPLES / "sample_run.csv")
    json_points, json_meta = ptm.load_log(SAMPLES / "sample_run.json")
    assert csv_points == json_points
    assert csv_meta == json_meta


def test_load_jsonl(tmp_path):
    path = tmp_path / "log.jsonl"
    path.write_text(
        '{"step": 1, "train_loss": 2.0, "model_name": "m"}\n\n'
        '{"step": 2, "train_loss": 1.5, "val_loss": 1.8}\n'
    )
    points, meta = ptm.load_log(path)
    assert points == [(1.0, 2.0, None), (2.0, 1.5, 1.8)]
    assert meta == {"model_name": "m"}


def test_validation_loss_is_optional(tmp_path):
    path = tmp_path / "log.json"
    path.write_text(json.dumps([{"step": 1, "train_loss": 1.0}, {"step": 2, "train_loss": 0.9}]))
    points, meta = ptm.load_log(path)
    assert all(v is None for _, _, v in points)
    assert meta == {}


def test_steps_are_sorted(tmp_path):
    path = tmp_path / "log.json"
    path.write_text(json.dumps([
        {"step": 20, "train_loss": 0.5},
        {"step": 10, "train_loss": 1.0},
    ]))
    points, _ = ptm.load_log(path)
    assert [p[0] for p in points] == [10, 20]


@pytest.mark.parametrize("name, content", [
    ("empty.json", ""),
    ("bad.json", "{not json"),
    ("nolosses.json", '[{"step": 1}]'),
    ("nostep.json", '[{"train_loss": 1.0}]'),
    ("nan.csv", "step,train_loss\n1,abc\n"),
    ("header_only.csv", "step,train_loss,val_loss\n"),
    ("notes.txt", "step,train_loss\n1,1.0\n"),
])
def test_malformed_input_raises(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content)
    with pytest.raises(ptm.LogError):
        ptm.load_log(path)


def test_missing_file_raises(tmp_path):
    with pytest.raises(ptm.LogError):
        ptm.load_log(tmp_path / "nope.json")


@pytest.mark.parametrize("sample", ["sample_run.json", "sample_run.csv"])
def test_main_writes_png(tmp_path, sample):
    pytest.importorskip("matplotlib")
    out = tmp_path / "curves.png"
    assert ptm.main([str(SAMPLES / sample), "--output", str(out), "--title", "t"]) == 0
    assert out.read_bytes().startswith(b"\x89PNG")
    assert out.stat().st_size > 1000


def test_main_train_only_writes_png(tmp_path):
    pytest.importorskip("matplotlib")
    log = tmp_path / "log.json"
    log.write_text(json.dumps([{"step": 2, "train_loss": 0.9}, {"step": 1, "train_loss": 1.0}]))
    assert ptm.main([str(log)]) == 0
    assert (tmp_path / "log_curves.png").stat().st_size > 1000


def test_main_bad_input_returns_nonzero(tmp_path, capsys):
    log = tmp_path / "log.json"
    log.write_text("")
    assert ptm.main([str(log)]) == 1
    assert "error:" in capsys.readouterr().err
    assert not (tmp_path / "log_curves.png").exists()
