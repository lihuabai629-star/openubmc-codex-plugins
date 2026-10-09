#!/usr/bin/env python3
"""Export, verify or explicitly prune private offline Task records."""
import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from openubmc_target_runtime.measurements import JsonMeasurementReader
from openubmc_target_runtime.record_export import RecordExportStore, export_task_records, verify_export
import json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("--handoff", type=Path, required=True)
    export.add_argument("--producer-commit", required=True)
    export.add_argument("--evidence", type=Path)
    export.add_argument("--output-directory", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("path", type=Path)
    prune = commands.add_parser("prune")
    prune.add_argument("--output-directory", type=Path, required=True)
    prune.add_argument("--before-timestamp", type=float, required=True)
    prune.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "verify":
            result = {"content_digest": verify_export(JsonMeasurementReader(args.path)(None, ()))}
        elif args.command == "export":
            evidence = None
            if args.evidence:
                try:
                    evidence = JsonMeasurementReader(args.evidence)(None, ())
                except Exception:
                    pass
            document = export_task_records(JsonMeasurementReader(args.handoff)(None, ()),
                producer_commit=args.producer_commit, evidence_snapshot=evidence)
            path = RecordExportStore(args.output_directory).write(document)
            result = {"path": str(path), "content_digest": document["content_digest"]}
        else:
            result = {"dry_run": not args.apply, "files": RecordExportStore(args.output_directory).prune(
                before_timestamp=args.before_timestamp, dry_run=not args.apply)}
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print("Task record export is unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
