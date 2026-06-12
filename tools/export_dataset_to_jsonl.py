#!/usr/bin/env python3
"""Convert a CPE Editor dataset export into one streaming NDJSON file.

The Flask ``export-app-dataset`` command writes one large ``dataset.json`` file
inside a portable tar.gz archive. This tool rewrites that export as newline-
delimited JSON without loading the whole dataset into memory: each top-level
record array is parsed and emitted one row at a time.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tarfile
from pathlib import Path
from typing import Any, Iterator, TextIO

DATASET_FORMAT = "cpe-editor-dataset"
DATASET_VERSION = "1"
RECORD_ARRAYS = (
    "vendors",
    "products",
    "cpes",
    "metadata",
    "relationships",
    "purl_mappings",
    "aliases",
    "proposals",
)


class StreamingJsonError(ValueError):
    """Raised when the input JSON cannot be parsed by the streaming converter."""


class StreamingJsonReader:
    """Small pull parser for the dataset export shape.

    The parser only materializes one JSON value at a time. That keeps memory use
    bounded by the largest individual record instead of the full export size.
    """

    def __init__(self, input_file: TextIO):
        self.input_file = input_file
        self._peeked = ""

    def read_char(self) -> str:
        if self._peeked:
            char = self._peeked
            self._peeked = ""
            return char
        return self.input_file.read(1)

    def peek_char(self) -> str:
        if not self._peeked:
            self._peeked = self.input_file.read(1)
        return self._peeked

    def skip_whitespace(self) -> None:
        while True:
            char = self.peek_char()
            if char and char in " \t\r\n":
                self.read_char()
                continue
            return

    def expect(self, expected: str) -> None:
        self.skip_whitespace()
        actual = self.read_char()
        if actual != expected:
            raise StreamingJsonError(f"Expected {expected!r}, found {actual!r}.")

    def read_json_string(self) -> str:
        self.skip_whitespace()
        raw = self._read_json_string_raw()
        return json.loads(raw)

    def _read_json_string_raw(self) -> str:
        quote = self.read_char()
        if quote != '"':
            raise StreamingJsonError(f"Expected JSON string, found {quote!r}.")

        raw = ['"']
        escaped = False
        while True:
            char = self.read_char()
            if not char:
                raise StreamingJsonError("Unexpected end of file inside JSON string.")
            raw.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                return "".join(raw)

    def read_json_value_text(self) -> str:
        self.skip_whitespace()
        first = self.peek_char()
        if not first:
            raise StreamingJsonError("Unexpected end of file while reading JSON value.")
        if first == '"':
            return self._read_json_string_raw()
        if first in "[{":
            return self._read_balanced_json_value()
        return self._read_scalar_json_value()

    def _read_balanced_json_value(self) -> str:
        raw: list[str] = []
        stack: list[str] = []
        in_string = False
        escaped = False

        while True:
            char = self.read_char()
            if not char:
                raise StreamingJsonError("Unexpected end of file inside JSON value.")
            raw.append(char)

            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
            elif char in "[{":
                stack.append("}" if char == "{" else "]")
            elif char in "]}":
                if not stack or stack[-1] != char:
                    raise StreamingJsonError(f"Unexpected closing delimiter {char!r}.")
                stack.pop()
                if not stack:
                    return "".join(raw)

    def _read_scalar_json_value(self) -> str:
        raw: list[str] = []
        while True:
            char = self.peek_char()
            if not char or char in ",}] \t\r\n":
                if not raw:
                    raise StreamingJsonError("Expected JSON scalar value.")
                return "".join(raw)
            raw.append(self.read_char())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Stream a CPE Editor dataset export into a single newline-delimited "
            "JSON file without loading the full export into memory."
        )
    )
    parser.add_argument(
        "source",
        help="Path to cpe-editor-dataset.tar.gz or a plain dataset JSON file.",
    )
    parser.add_argument(
        "output",
        help="Destination .jsonl/.ndjson file, or '-' to write to stdout.",
    )
    args = parser.parse_args(argv)

    counts = export_dataset_to_jsonl(Path(args.source), args.output)
    status_file = sys.stderr if args.output == "-" else sys.stdout
    print(
        "Wrote NDJSON export to "
        f"{args.output} "
        f"(vendors={counts['vendors']}, products={counts['products']}, "
        f"cpes={counts['cpes']}, metadata={counts['metadata']}, "
        f"relationships={counts['relationships']}, "
        f"purl_mappings={counts['purl_mappings']}, aliases={counts['aliases']}, "
        f"proposals={counts['proposals']})",
        file=status_file,
    )
    return 0


def export_dataset_to_jsonl(source: Path, output: str | Path) -> dict[str, int]:
    """Convert ``source`` into one NDJSON file and return emitted row counts."""
    with (
        open_dataset_text(source) as input_file,
        open_output_text(output) as output_file,
    ):
        return write_dataset_jsonl(input_file, output_file)


@contextlib.contextmanager
def open_dataset_text(source: Path) -> Iterator[TextIO]:
    if source.suffix == ".json":
        with source.open("r", encoding="utf-8") as input_file:
            yield input_file
        return

    with tarfile.open(source, mode="r:gz") as archive:
        member = None
        fallback_member = None
        for item in archive:
            if not item.isfile():
                continue
            if item.name.endswith("dataset.json"):
                member = item
                break
            if fallback_member is None and item.name.endswith(".json"):
                fallback_member = item
        if member is None:
            member = fallback_member
        if member is None:
            raise SystemExit("Could not find dataset.json in the export archive.")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise SystemExit("Could not extract dataset.json from the export archive.")
        with extracted, io.TextIOWrapper(extracted, encoding="utf-8") as input_file:
            yield input_file


@contextlib.contextmanager
def open_output_text(output: str | Path) -> Iterator[TextIO]:
    if str(output) == "-":
        yield sys.stdout
        return

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        yield output_file


def write_dataset_jsonl(input_file: TextIO, output_file: TextIO) -> dict[str, int]:
    reader = StreamingJsonReader(input_file)
    counts = {name: 0 for name in RECORD_ARRAYS}
    header: dict[str, Any] = {}
    wrote_header = False

    reader.expect("{")
    reader.skip_whitespace()
    if reader.peek_char() == "}":
        reader.read_char()
        raise SystemExit("Dataset export is empty.")

    while True:
        key = reader.read_json_string()
        reader.expect(":")

        if key in RECORD_ARRAYS:
            if not wrote_header:
                validate_dataset_header(header)
                write_jsonl_row(output_file, {"type": "dataset", **header})
                wrote_header = True
            counts[key] = write_record_array(reader, output_file, key)
        else:
            value = json.loads(reader.read_json_value_text())
            if key in {"format", "version", "exported_at", "counts"}:
                header[key] = value

        reader.skip_whitespace()
        separator = reader.read_char()
        if separator == ",":
            continue
        if separator == "}":
            break
        raise StreamingJsonError(f"Expected ',' or '}}', found {separator!r}.")

    if not wrote_header:
        validate_dataset_header(header)
        write_jsonl_row(output_file, {"type": "dataset", **header})

    return counts


def validate_dataset_header(header: dict[str, Any]) -> None:
    if header.get("format") != DATASET_FORMAT:
        raise SystemExit(
            f"Unsupported dataset format {header.get('format')!r}; expected {DATASET_FORMAT!r}."
        )
    if str(header.get("version")) != DATASET_VERSION:
        raise SystemExit(
            f"Unsupported dataset version {header.get('version')!r}; expected {DATASET_VERSION!r}."
        )


def write_record_array(
    reader: StreamingJsonReader, output_file: TextIO, collection: str
) -> int:
    count = 0
    reader.expect("[")
    reader.skip_whitespace()
    if reader.peek_char() == "]":
        reader.read_char()
        return count

    while True:
        record = json.loads(reader.read_json_value_text())
        write_jsonl_row(
            output_file,
            {"type": "record", "collection": collection, "record": record},
        )
        count += 1

        reader.skip_whitespace()
        separator = reader.read_char()
        if separator == ",":
            continue
        if separator == "]":
            return count
        raise StreamingJsonError(f"Expected ',' or ']', found {separator!r}.")


def write_jsonl_row(output_file: TextIO, row: dict[str, Any]) -> None:
    output_file.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
    output_file.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
