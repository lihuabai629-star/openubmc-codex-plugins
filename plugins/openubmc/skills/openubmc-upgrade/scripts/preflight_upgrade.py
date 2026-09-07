#!/usr/bin/env python3
"""Validate one Upgrade artifact and inspect one target without uploading."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import importlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit


SCHEMA = "openubmc-upgrade.preflight.v1"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--artifact-path", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--product-version", required=True)
    parser.add_argument(
        "--upgrade-protocol",
        choices=("auto", "redfish", "webui"),
        default="auto",
    )
    parser.add_argument(
        "--verification-mode",
        choices=("auto", "manager-version", "task-completion"),
        default="auto",
    )
    parser.add_argument("--image-uri", default="")
    parser.add_argument("--credentials-file", default="")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--allow-insecure-tls", action="store_true")
    parser.add_argument(
        "--probe-upload-options",
        action="store_true",
        help="Issue read-only OPTIONS requests to advertised upload endpoints.",
    )
    return parser.parse_args(argv)


def advertised_methods(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return []
    methods: list[str] = []
    if isinstance(payload.get("MultipartHttpPushUri"), str) and payload.get(
        "MultipartHttpPushUri"
    ):
        methods.append("MultipartHttpPushUri")
    if isinstance(payload.get("HttpPushUri"), str) and payload.get("HttpPushUri"):
        methods.append("HttpPushUri")
    actions = payload.get("Actions")
    simple = (
        actions.get("#UpdateService.SimpleUpdate")
        if isinstance(actions, dict)
        else None
    )
    if isinstance(simple, dict) and isinstance(simple.get("target"), str):
        methods.append("SimpleUpdate")
    return methods


def advertised_uris(payload: object) -> dict[str, str]:
    if not isinstance(payload, dict):
        return {}
    uris: dict[str, str] = {}
    for name in ("MultipartHttpPushUri", "HttpPushUri"):
        value = payload.get(name)
        if isinstance(value, str) and value:
            uris[name] = value
    actions = payload.get("Actions")
    simple = (
        actions.get("#UpdateService.SimpleUpdate")
        if isinstance(actions, dict)
        else None
    )
    if isinstance(simple, dict) and isinstance(simple.get("target"), str):
        uris["SimpleUpdate"] = simple["target"]
    return uris


def advertised_max_image_size(payload: object) -> int | None:
    if not isinstance(payload, dict):
        return None
    value = payload.get("MaxImageSizeBytes")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def compatibility_warnings(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return []
    multipart = payload.get("MultipartHttpPushUri")
    http_push = payload.get("HttpPushUri")
    if (
        not isinstance(multipart, str)
        or not multipart
    ) and isinstance(http_push, str) and http_push.rstrip("/").endswith(
        "/FirmwareInventory"
    ):
        return ["legacy-http-push-collection-endpoint"]
    return []


def upload_plan(payload: object) -> dict[str, object]:
    """Return the first-write encoding and any staged activation requirement."""

    if not isinstance(payload, dict):
        return {}
    methods = advertised_methods(payload)
    if not methods:
        return {}
    method = methods[0]
    if method == "MultipartHttpPushUri":
        return {
            "method": method,
            "encoding": "multipart/form-data",
            "staged_activation_required": False,
        }
    if method == "HttpPushUri":
        legacy = "legacy-http-push-collection-endpoint" in compatibility_warnings(
            payload
        )
        simple = payload.get("Actions")
        simple = (
            simple.get("#UpdateService.SimpleUpdate")
            if isinstance(simple, dict)
            else None
        )
        return {
            "method": method,
            "encoding": (
                "multipart/form-data" if legacy else "application/octet-stream"
            ),
            "compatibility_mode": "legacy-http-push-multipart" if legacy else "",
            "staged_activation_required": bool(
                legacy and isinstance(simple, dict) and isinstance(simple.get("target"), str)
            ),
        }
    return {
        "method": method,
        "encoding": "application/json",
        "staged_activation_required": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    skill_root = Path(__file__).resolve().parents[1]
    repo_root = skill_root.parent
    sys.path.insert(0, str(repo_root / "openubmc-target-runtime"))
    sys.path.insert(0, str(skill_root))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    artifact_identity = importlib.import_module("artifact_identity")
    credentials_module = importlib.import_module("redfish_credentials")
    backend = importlib.import_module("openubmc_upgrade.runtime_backend")

    try:
        origin = credentials_module.target_origin(args.target)
        credential_path = args.credentials_file or credentials_module.os.environ.get(
            "OPENUBMC_CREDENTIALS_FILE",
            "",
        )
        if not credential_path:
            raise ValueError("OPENUBMC_CREDENTIALS_FILE is not configured")
        credentials = credentials_module.load_credentials(Path(credential_path))
        identity = artifact_identity.stable_sha256(Path(args.artifact_path))
        expected_sha = args.artifact_sha256.strip().lower()
        if identity["sha256"] != expected_sha:
            raise ValueError("artifact SHA-256 does not match")
        if not args.product_version.strip():
            raise ValueError("product version must not be empty")
        metadata = backend.validate_artifact_metadata(
            Path(args.artifact_path).absolute(),
            expected_sha256=expected_sha,
            product_version=args.product_version,
            actual_size=int(identity["size"]),
        )

        parsed = urlsplit(origin)
        target = backend.TargetSpec.for_credential_selectors(
            host=str(parsed.hostname),
            redfish_port=int(parsed.port or 443),
            credential_selectors=(
                backend.CredentialSelector.for_redfish(
                    user=credentials.user,
                    user_env="",
                    password_env="",
                    environ={},
                ),
            ),
            policy=backend.TargetPolicy(read_only=True),
        )
        session = backend.RedfishHttpSession(
            target=target,
            credentials=credentials,
            verify_tls=not args.allow_insecure_tls,
            timeout=args.timeout,
        )
        update_service = session.request_json("GET", "/redfish/v1/UpdateService")
        methods = advertised_methods(update_service.payload)
        method_uris = advertised_uris(update_service.payload)
        selected_plan = backend._upgrade_upload_plan(
            update_service.payload,
            {
                "upgrade_protocol": args.upgrade_protocol,
                "verification_mode": args.verification_mode,
                "image_uri": args.image_uri,
            },
        )
        selected_protocol = str(selected_plan.get("protocol", "redfish"))
        selected_verification = backend._resolved_verification_mode(
            {"verification_mode": args.verification_mode},
            selected_protocol,
        )
        webui_probe = (
            backend.UpgradeMcpBackend._probe_webui(session)
            if selected_protocol == "webui"
            else None
        )
        if selected_protocol == "webui":
            methods = [*methods, "WebUI"]
        max_image_size = advertised_max_image_size(update_service.payload)
        artifact_size = int(identity["size"])
        if max_image_size is not None and artifact_size > max_image_size:
            raise ValueError(
                "artifact exceeds the target-advertised MaxImageSizeBytes: "
                f"artifact {artifact_size}, maximum {max_image_size}"
            )
        installed = backend.UpgradeMcpBackend._installed_version(session)
        current_version = str(installed["version"])
        activation_state = backend.UpgradeMcpBackend._activation_state(
            session,
            manager_version=current_version,
            expected_version=args.product_version,
        )
        option_probes: dict[str, object] = {}
        if args.probe_upload_options:
            for method, uri in method_uris.items():
                try:
                    response = session.request_json("OPTIONS", uri)
                except backend.RedfishHttpError as exc:
                    option_probes[method] = {
                        "status": exc.status,
                        "accepted": False,
                    }
                else:
                    option_probes[method] = {
                        "status": response.status,
                        "accepted": 200 <= response.status < 300,
                        "allow": str(response.headers.get("Allow", "")),
                    }
        document = {
            "schema": SCHEMA,
            "ok": True,
            "target": origin,
            "artifact": identity,
            "expected_product_version": args.product_version,
            "current_product_version": current_version,
            "version_change_required": current_version != args.product_version,
            "advertised_methods": methods,
            "selected_method": selected_plan["method"],
            "selected_protocol": selected_protocol,
            "verification_mode": selected_verification,
            "advertised_uris": method_uris,
            "upload_plan": selected_plan,
            "artifact_size_bytes": artifact_size,
            "artifact_metadata": metadata,
            "max_image_size_bytes": max_image_size,
            "compatibility_warnings": compatibility_warnings(
                update_service.payload
            ),
            "upload_option_probes": option_probes,
            "activation_state": activation_state,
            "webui_probe": webui_probe,
            "credentials_ready": True,
            "tls_verification": (
                "disabled" if args.allow_insecure_tls else "system"
            ),
        }
    except Exception as exc:
        document = {"schema": SCHEMA, "ok": False, "error": str(exc)}
    print(json.dumps(document, ensure_ascii=False, sort_keys=True))
    return 0 if document["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
