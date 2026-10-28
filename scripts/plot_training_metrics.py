#!/usr/bin/env python3
"""Plot training and validation loss from an exported training log.

Reads a log file only; it never touches the model or a running training job.
See "Plotting training metrics" in the README for the log format.

Usage:
    python3 scripts/plot_training_metrics.py examples/training_logs/sample_run.json
"""

import argparse
import csv
import json
import math
import sys
from pathlib import Path

METADATA_KEYS = ("model_name", "dataset_version", "checkpoint")


class LogError(Exception):
    """Raised when a training log cannot be read or has no usable data."""


def _to_float(value):
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise LogError(f"not a number: {value!r}")
    return number if math.isfinite(number) else None


def _normalize(rows, metadata):
    """Turn raw row dicts into sorted (step, train_loss, val_loss) tuples."""
    points = []
    for i, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise LogError(f"record {i} is not an object")
        for key in METADATA_KEYS:
            if row.get(key) not in (None, ""):
                metadata.setdefault(key, str(row[key]))
        step = _to_float(row.get("step"))
        if step is None:
            raise LogError(f"record {i} has no 'step'")
        train = _to_float(row.get("train_loss"))
        val = _to_float(row.get("val_loss"))
        if train is None and val is None:
            continue
        points.append((step, train, val))
    if not points:
        raise LogError("no records with train_loss or val_loss found")
    points.sort(key=lambda p: p[0])
    return points, metadata


def load_log(path):
    """Return (points, metadata) for a .json, .jsonl or .csv log file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise LogError(f"cannot read {path}: {exc.strerror or exc}")
    if not text.strip():
        raise LogError(f"{path} is empty")

    suffix = path.suffix.lower()
    metadata = {}
    try:
        if suffix == ".json":
            data = json.loads(text)
            if isinstance(data, dict):
                for key in METADATA_KEYS:
                    if data.get(key) not in (None, ""):
                        metadata[key] = str(data[key])
                rows = data.get("records")
            else:
                rows = data
            if not isinstance(rows, list):
                raise LogError("expected a list of records (or an object with 'records')")
        elif suffix == ".jsonl":
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        elif suffix == ".csv":
            rows = list(csv.DictReader(text.splitlines()))
        else:
            raise LogError(f"unsupported file type {suffix!r} (use .json, .jsonl or .csv)")
        return _normalize(rows, metadata)
    except json.JSONDecodeError as exc:
        raise LogError(f"invalid JSON in {path}: {exc}")
    except LogError as exc:
        raise LogError(f"{path}: {exc}")


def plot_metrics(points, metadata, output, title=None):
    """Draw the loss curves and save them to `output` as a PNG."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise LogError("matplotlib is required for plotting: pip install matplotlib")

    train = [(s, t) for s, t, _ in points if t is not None]
    val = [(s, v) for s, _, v in points if v is not None]

    fig, ax = plt.subplots(figsize=(9, 5))
    if train:
        ax.plot(*zip(*train), label="Training loss", color="#1f77b4")
    if val:
        ax.plot(*zip(*val), label="Validation loss", color="#d95f02", marker="o", markersize=3)
    ax.set_xlabel("Training step")
    ax.set_ylabel("Loss")
    ax.grid(True, alpha=0.3)
    ax.legend()

    ax.set_title(title or metadata.get("model_name") or "Training metrics")
    labels = {
        "model_name": "Model",
        "dataset_version": "Dataset",
        "checkpoint": "Checkpoint",
    }
    details = [f"{labels[k]}: {metadata[k]}" for k in METADATA_KEYS if k in metadata]
    if details:
        fig.text(0.5, 0.01, "   |   ".join(details), ha="center", fontsize=9, color="#555555")
    fig.tight_layout(rect=(0, 0.04 if details else 0, 1, 1))

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=150)
    plt.close(fig)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Plot training/validation loss from an exported training log."
    )
    parser.add_argument("input", help="training log (.json, .jsonl or .csv)")
    parser.add_argument(
        "-o", "--output",
        help="output PNG path (default: <input name>_curves.png next to the input)",
    )
    parser.add_argument("--title", help="plot title (default: model name)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    input_path = Path(args.input)
    output = Path(args.output) if args.output else input_path.with_name(input_path.stem + "_curves.png")
    try:
        points, metadata = load_log(input_path)
        plot_metrics(points, metadata, output, args.title)
    except LogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {output} ({len(points)} points)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
