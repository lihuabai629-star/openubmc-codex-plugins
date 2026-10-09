import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "analyze_redfish_diff.py"
SPEC = importlib.util.spec_from_file_location("analyze_redfish_diff", SCRIPT)
analyzer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analyzer)


def entries(mapping):
    return analyzer.collect_entries_from_mapping(mapping, "interface_config/redfish/mapping_config/Test/Test.json")


class SemanticDiffTests(unittest.TestCase):
    def test_password_request_body_is_object_and_references_are_annotated(self):
        new_mapping = {
            "Resources": [
                {
                    "Uri": "/redfish/v1/Test/Actions/Test.VerifyPassword",
                    "Interfaces": [
                        {
                            "Type": "POST",
                            "ResourceExist": {"${Statements/IsValid()}": True},
                            "ReqBody": {
                                "Type": "object",
                                "Required": True,
                                "Properties": {
                                    "Password": {
                                        "Type": "string",
                                        "Required": True,
                                        "Sensitive": True,
                                        "Validator": [{"Type": "Length", "Formula": [0, 512]}],
                                    },
                                    "SessionAccountPassword": {
                                        "Type": "string",
                                        "Required": True,
                                        "Sensitive": True,
                                        "Validator": [{"Type": "Length", "Formula": [0, 512]}],
                                    },
                                },
                            },
                            "RspBody": {
                                "MessageId": "${Statements/GetMessageId()}",
                                "Message": "Password Verify successfully.",
                            },
                            "RspHeader": {"X-Trace": "${ProcessingFlow[0]/Destination/TraceId}"},
                            "Statements": {
                                "IsValid": {"Steps": [{"Type": "Script", "Formula": "return true"}]},
                                "GetMessageId": {
                                    "Steps": [
                                        {"Type": "Plugin", "Formula": "utils.get_registry_prefix()"},
                                        {"Type": "Suffix-Add", "Formula": ".1.0.VerifyPasswordSuccess"},
                                    ]
                                },
                                "IsAuthSuccess": {
                                    "Input": "${ProcessingFlow[0]/Destination/UserId}",
                                    "Steps": [
                                        {
                                            "Type": "Script",
                                            "Formula": "if Input == nil then return false else return true end",
                                        }
                                    ],
                                },
                            },
                            "ProcessingFlow": [
                                {
                                    "Type": "Method",
                                    "Name": "Authenticate",
                                    "Params": ["${ReqBody/SessionAccountPassword}"],
                                    "Destination": {"UserId": "UserId", "TraceId": "TraceId"},
                                },
                                {
                                    "Type": "Method",
                                    "Name": "VerifyPassword",
                                    "Params": ["${ReqBody/Password}"],
                                    "CallIf": {"${Statements/IsAuthSuccess()}": True},
                                },
                            ],
                        }
                    ],
                }
            ]
        }
        rows, details = analyzer.diff_entries({}, entries(new_mapping))
        self.assertEqual(len(rows), 1)
        full = rows[0]["_added_definition"]
        paths = [row["path"] for row in full]
        self.assertIn("ReqBody/Password", paths)
        self.assertNotIn("ReqBody/Properties/Password/Type", paths)
        self.assertFalse(any(path.startswith("Statements/") or path.startswith("ProcessingFlow[") for path in paths))
        password = next(row for row in full if row["path"] == "ReqBody/Password")
        self.assertEqual(password["type"], "Object")
        self.assertIn("敏感信息", password["value"])
        self.assertIn("Length[0, 512]", password["value"])
        self.assertIn("VerifyPassword", password["reference_note"])
        message_id = next(row for row in full if row["path"] == "RspBody/MessageId")
        self.assertIn("Statements/GetMessageId()", message_id["reference_note"])
        self.assertTrue(any(d["path"] == "RspHeader/X-Trace" for d in details))

    def test_multiple_statement_changes_are_mapped_to_all_response_callers(self):
        base = {
            "Resources": [
                {
                    "Uri": "/redfish/v1/Test",
                    "Interfaces": [
                        {
                            "Type": "GET",
                            "RspBody": {"A": "${Statements/A()}", "B": "${Statements/B()}"},
                            "Statements": {
                                "A": {"Steps": [{"Type": "Suffix-Add", "Formula": "old-a"}]},
                                "B": {"Steps": [{"Type": "Suffix-Add", "Formula": "old-b"}]},
                            },
                        }
                    ],
                }
            ]
        }
        changed = {
            "Resources": [
                {
                    "Uri": "/redfish/v1/Test",
                    "Interfaces": [
                        {
                            "Type": "GET",
                            "RspBody": {"A": "${Statements/A()}", "B": "${Statements/B()}"},
                            "Statements": {
                                "A": {"Steps": [{"Type": "Suffix-Add", "Formula": "new-a"}]},
                                "B": {"Steps": [{"Type": "Suffix-Add", "Formula": "new-b"}]},
                            },
                        }
                    ],
                }
            ]
        }
        rows, details = analyzer.diff_entries(entries(base), entries(changed))
        self.assertEqual(len(rows), 1)
        notes = {d["path"]: d["reference_note"] for d in details}
        self.assertIn("RspBody/A", notes)
        self.assertIn("RspBody/B", notes)
        self.assertIn("Statements/A()", notes["RspBody/A"])
        self.assertIn("Statements/B()", notes["RspBody/B"])

    def test_headers_are_reported_only_when_changed(self):
        old = {
            "Resources": [
                {"Uri": "/redfish/v1/Test", "Interfaces": [{"Type": "GET", "RspHeader": {"X-Auth-Token": "old"}}]}
            ]
        }
        new = {
            "Resources": [
                {"Uri": "/redfish/v1/Test", "Interfaces": [{"Type": "GET", "RspHeader": {"X-Auth-Token": "new"}}]}
            ]
        }
        rows, details = analyzer.diff_entries(entries(old), entries(new))
        self.assertIn("响应头内容变化", rows[0]["categories"])
        self.assertTrue(any(d["path"] == "RspHeader/X-Auth-Token" for d in details))

    def test_request_schema_summarizes_arrays_and_validators(self):
        surface = analyzer.build_req_surface(
            {
                "Type": "object",
                "Properties": {
                    "Mode": {"Type": ["number", "boolean"], "Validator": [{"Type": "Enum", "Formula": [1, True]}]},
                    "Ports": {
                        "Type": "array",
                        "Items": {"Type": "integer"},
                        "minItems": 1,
                        "maxItems": 4,
                        "uniqueItems": True,
                        "Validator": [{"Type": "Range", "Formula": [1, 65535]}],
                    },
                    "Tuple": {"Type": "array", "Items": [{"Type": "number"}, {"Type": "string"}]},
                    "Pattern": {
                        "Type": "string",
                        "Validator": [
                            {"Type": "Regex", "Formula": "^x+$"},
                            {"Type": "Script", "Formula": "return true"},
                        ],
                    },
                },
            }
        )
        self.assertIn("Enum[1, True]", surface["ReqBody/Mode"]["value"])
        self.assertIn("Range[1, 65535]", surface["ReqBody/Ports"]["value"])
        self.assertIn("Items(tuple:", surface["ReqBody/Tuple"]["value"])
        self.assertIn("Regex", surface["ReqBody/Pattern"]["value"])
        self.assertIn("Script", surface["ReqBody/Pattern"]["value"])


if __name__ == "__main__":
    unittest.main()
