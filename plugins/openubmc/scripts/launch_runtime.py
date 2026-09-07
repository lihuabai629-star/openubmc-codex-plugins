#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import runpy
import sys
import tempfile

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / 'skills/openubmc-target-runtime/openubmc_target_runtime'
MCP_ENTRYPOINT = Path(__file__).resolve().parents[1] / 'skills/openubmc-debug/scripts/target_runtime_mcp.py'
EXPECTED_API = "openubmc.target-runtime.v1"
EXPECTED_DIGEST = "sha256:c05f5bde3fc0db19f78e90fe2d5a1746ce8c7bb3d4f9c4ae7ba676a9f70365e3"
EXPECTED_ENTRYPOINT_DIGEST = "sha256:86b460bfa462b37e872bcd526843a0ae332a7c4cd01a6aa178a1590387bdcf87"
COMPOSITION_SOURCE = Path(__file__).resolve().parents[1] / 'skills'
COMPOSITION_FILES = {'lua-component/SKILL.md': '16fa78b8ca9f127134758d7b6999a53ecaa2137c240f7f85fc6ee712152c8b67', 'lua-component/agents/openai.yaml': '08dc82afd1e8d0e14ccd1cedfaa9a5e5d23a320f8a8bfd9f24669092ebed2a63', 'lua-component/skill.json': '80bf5c44b4aaf2868cc9013093b5a5809b9f758027505465d9d62eab8e80ba58', 'openubmc-build/SKILL.md': 'c81d5e9bff835e05e8ed0df5c96b0912a946cdc3e03c3a0376a9abd42ff6cc59', 'openubmc-build/agents/openai.yaml': '9fa2ad6d3de4a79b2bac163765bb0d7a4cc0ae956b35c6b0dc9158cc2bb7f17e', 'openubmc-build/references/2630-wsl-profile.md': '55f47c5efde498dc6f82022c108dad5085b5ff1cff8769b73cc51e7d2cb1b3d5', 'openubmc-build/references/artifact-verification.md': '1356317d109410b23e59037b2afd8202001a1b6280edbdd6420cffc59a800e88', 'openubmc-build/references/build-plan.md': '23a341490120402032fa9e84f1e67ba7b081feb13b0777565b0bd5fe0bcc173f', 'openubmc-build/references/conan-auth.md': '282f6d32a1055df0e609a2e81a9e028762b3935218dd1599d04d05337670c46f', 'openubmc-build/references/handoff-contract.md': '088d32064cfb2c24cb27dc8d08874da1cbe81e63688b82036c8d241ca2f0aeb5', 'openubmc-build/references/modes/component-package.md': 'f66fee6fd5e6d56c8780e4613bd5e008634bbe0444043efabb6e7083d1ed999c', 'openubmc-build/references/modes/diagnose.md': '9cee2e5daa8885f5c9378acb6e5edda3c1ea2f321c54c7064445b158594d9e07', 'openubmc-build/references/modes/product-artifact.md': 'f6f8fd4e2dafd1b0633d0177ca0bee962eb98437a79c7a852ebe4caee19865a9', 'openubmc-build/references/modes/publish.md': '5e830c25953d2ae9c92f07c354ed30c4692719186189660679dde4ac91f5ddea', 'openubmc-build/references/modes/validate.md': 'e447d40bc19b9f19312d387499bbd8f0bbca3e267615df07906789a86ee268a7', 'openubmc-build/references/product-build-pitfalls.md': 'fc7c960448bc6e008db49ee77e3ecc3e81b54f62cec87ae89e2d154deb56dfc2', 'openubmc-build/references/redfish-upgrade.md': '7677bdeeae87a060a7496687d027ef30b3ff379c4cc07cf148b0e4ecebe04b24', 'openubmc-build/requirements-containment.txt': '6826a8358c3fbc21c12fd74cd83771ea62cf83b07be2712ce1aa3da284ae67ab', 'openubmc-build/scripts/check_dependency_delta.py': 'a290493df4971596df628d4ef44905427a9facd867527937f5bd8b70d05d047b', 'openubmc-build/scripts/check_rootfs_access.py': '4e15209e8e7f98321132896f94a8ecc51ce7e75cd2d9e10228395840a13a7e72', 'openubmc-build/scripts/create_build_plan.py': 'eb9630405553bf1376ee0b1ce1098f8a4d7227aca1119279c16945856217ea92', 'openubmc-build/scripts/detect_changed_components.py': 'e7d320f1c8582ceff5e96c2d947f17dc2b892c905d29163b1f4ccfd615ba7aa1', 'openubmc-build/scripts/ensure_planned_version.py': '9abe082b0d087ccef42b53d4717cf6437491ba3c0adfec10c14f07be673afb92', 'openubmc-build/scripts/finalize_product_attempt.py': '22e574d1f66fa9911c18157caa78960882f1d622b3beb9d0d196946ff8e88190', 'openubmc-build/scripts/preflight_build_env.sh': 'c0e8c43d604de36919a98f10dba5ea093f47ef5b1680816444d2f6cce76e8d6c', 'openubmc-build/scripts/run_bmcgo_checked.py': '90e49f33a7273f32278ef9530fd2bcc4a1417d50830446bb7ece637465dfd009', 'openubmc-build/scripts/run_build_attempt.py': '6fc06c6f703bc44c4d6fe7fafa2efb00bef6037927e5756894de251b78ac92bb', 'openubmc-build/scripts/update_manifest_conan_ref.py': '3067585ff788d29fe24cd1310cd5f243dd9df433dd277028e68126dae01aaebc', 'openubmc-build/scripts/verify_hpm_containment.py': '71c1fa6543dda7e324ef8bb690a30318541552a11c6aa06a6442382c416a985b', 'openubmc-build/scripts/verify_product_artifact.py': '5b6296a4ce47d16da18bfa7ae8c2b8cfeda359afa134393a480024e56c29bcaa', 'openubmc-build/scripts/write_artifact_metadata.py': '49cc52eace1048f9b5f91b4fce2ad3f21c9c6117909158a64dabf40160bbe3b5', 'openubmc-build/skill.json': 'a6d4285c55c04c314f113999af548868c1801522e07762ce391313d59bbe0414', 'openubmc-debug/SKILL.md': 'f4c87da8edb2ff6cdd31f72de8880157e36f349c75d84703d2da8a683e5f8001', 'openubmc-debug/agents/openai.yaml': 'ad7d59367eb9abfd743d205d89066d0e96c88fb426978a2a29999407d7f81c34', 'openubmc-debug/references/agent-gateway.md': '27d6cab388362c9b1bcc41b086a6cdd2139bfbb228934bf2014a364354729c81', 'openubmc-debug/references/alarm-access.md': 'fdf6ea9e5d52f2fd3af7b55fb311e4c5f794c0c7e0f74389af88b430ae067e49', 'openubmc-debug/references/busctl-access.md': '7e08711311545e414865669a721f03629316a5ab37e9779a45d18a75df7fc0b6', 'openubmc-debug/references/components.md': '013327abb03a501bbc1678e912e482297cf26a9069323067d80590d8debd2457', 'openubmc-debug/references/diagnostic-contract.md': '84b54f86259347ec1487b8bf548282e2cd437f85bf89a0d768845233d472c296', 'openubmc-debug/references/evidence-workflow.md': '48f23e182783d0cf448136229a5765f768a8a7f8a0b69c046524075f812ff691', 'openubmc-debug/references/file-access.md': '5041b5a16acb4c40bee95932d84fde219d29e49198f8cac3b2a754c45933ed60', 'openubmc-debug/references/knowledge-routing.md': 'a49898fd45fd2f77c7fc8b776426d942c6c9ec597d97a3a8278ed403ffbaf935', 'openubmc-debug/references/logs.md': '334204de8c0febbf6c13c0b6dbd69ea032977ca4e95b025c2bcba3368de7d7ca', 'openubmc-debug/references/mdbctl-access.md': 'c1d212dd685ef955b9dd3d24a5be77e5757020a5681693f92f58f2fe4d4217f6', 'openubmc-debug/references/mechanism-debugging.md': '07759dcf4fc4529682d91355b01a562767f53d65ab0f9f011def5c02f8b20d66', 'openubmc-debug/references/object-access.md': '815d330e52822e6d6e6e914a2e8e7cf21ab60d3149a4d8eca1e054a12845a2b0', 'openubmc-debug/references/openubmc-debug-compare-v1.schema.json': '4312dc23c506e4b426cbab1445f9cab317cfd8e04f5f3bc5a5d75b2a1e8d72e9', 'openubmc-debug/references/optional-integrations.md': '4537c7dad1d53a9548fee324a64d25f8506cbbeeb619e0ca2685aa6d288eeb39', 'openubmc-debug/references/remote-automation.md': '273fa03abe185e23606af10ecf3f1b76263f249b0ba6bc78754305fc76f4f55a', 'openubmc-debug/references/workflow.md': '00802998533335ad3fe3e58d4527cfe809bebf7ad5996815a0fd7e5a81798de9', 'openubmc-debug/scripts/_cli_common.py': 'd3454be17b73e0b167f2d112f1f82e0e67d941a4fdc6e435128525e0310d5661', 'openubmc-debug/scripts/_comparison.py': 'adbe2e6946da5982b74065b50a5b9f49c0f206bb605b4ff984a605ea258a0365', 'openubmc-debug/scripts/_debug_dump.py': 'd62f7d5d5a4b7bed479f9d8aef92448fa918a8efbc0f330a932b1d5d1a13457e', 'openubmc-debug/scripts/_json_common.py': '25270e20f31c8f3f8d5762d08194299f7af52afdc15eb3a72331b3fbc0510b9a', 'openubmc-debug/scripts/_minimal_telnet.py': '3134df03634b8f8c600b00da7085c8291032864d2aceffab1fd63142b42dae98', 'openubmc-debug/scripts/_preflight_checks.py': 'ca7124ab8fccf6d97d798480af4200005f77c9bbc734e3e1b265ca2e3f226505', 'openubmc-debug/scripts/_preflight_recommendations.py': 'a55311f94ae8bac99a69189e95f6520336102355700d35666cc831cc2079a97f', 'openubmc-debug/scripts/_remote_common.py': 'b0e6f43ba4e3baae2c1259ccb35c2f9efcd423f84254b99055954d36ae631fd0', 'openubmc-debug/scripts/_runtime_distribution.py': 'e826e27173cfb40f8177fc280a0cfe9a36442e69018428761da37f374b6cd17b', 'openubmc-debug/scripts/_source_root.py': 'cebc7277650c3676d0b263fee6a885c9d94ba7be18fec40cd2550190fa35648a', 'openubmc-debug/scripts/_target_runtime_adapter.py': '5a3bb509e0c8976cf534c3d65a8f506179976ee3f887ffaea9d2a975bdc10620', 'openubmc-debug/scripts/_telnet_common.py': '4c4613c070f7e31c7c52cc7016fc2c7ce024110ef1685390532137ed3cfcf0c9', 'openubmc-debug/scripts/_workflow_contracts.py': '824bc12a457c2aca846ea194f2ef864d542b701e5bf4fb04eaf547f101eedab6', 'openubmc-debug/scripts/_workflow_correlation.py': '7b84ea4e9c50f1501bb5c00ce1d0b5aad06ae96f5180b7f73eadcc4851c7e48e', 'openubmc-debug/scripts/_workflow_freshness.py': '41db861161a670b779cc6adab437c189940cec9d2b7f31b6ad72ccd015336b75', 'openubmc-debug/scripts/_workflow_runtime.py': '698b05e16dd868827c6714e4559ac08b3e169461b6d77356fa697e1490fcd379', 'openubmc-debug/scripts/_workflow_source.py': '2f57732c6aab1a0b608cb8efd1a57978894567fa942ae2405828bea47c69ff3a', 'openubmc-debug/scripts/active_alarms.py': 'd932042aca3c3255a3e88552f5d24a6f4311fc9bcbcb6e80adfb2557ecc2990b', 'openubmc-debug/scripts/busctl_remote.py': 'da211ffd68a0ddf7fd5c6b8e33a0b7c0414673f4bd2add6b24f24bc7db0d8982', 'openubmc-debug/scripts/collect_logs.py': 'eaca4df922bb8d742f715e8d27f3c17c39f55c90792ea33d699f3db4cf4e44bc', 'openubmc-debug/scripts/compare_remote.py': '3064419cff2e252923eeb6c52affcec84373704685cad30ad86237ea0f97a807', 'openubmc-debug/scripts/doctor.py': 'e640617b084d093636bddde9c48def86d7477637259bf554ecc768a9331577bf', 'openubmc-debug/scripts/mdbctl_remote.py': '019b615f112bbb393868477a207929c1d87f774436cb3fa931b92328b9244097', 'openubmc-debug/scripts/package_skill.py': 'a35fb5a49ae12a513e13d8fbad79b9a96c36f05b0f9fdc4f707e70cbfa71c654', 'openubmc-debug/scripts/preflight_checks.py': 'ddc1e2f3d43e7e03d1db23c7e4b26940047dfb3fdcf72080db8a35698c83c965', 'openubmc-debug/scripts/preflight_recommendations.py': '3395957dd05ea792229e83ce5a58138a6044e334c1759b30f2a7bc952cc5c0a0', 'openubmc-debug/scripts/preflight_remote.py': '6ff2b551e5643e4a179cd3682c349c1164b55a300d1352a664d2a8934ff4ca4f', 'openubmc-debug/scripts/read_remote_file.py': '6093b8490536ba1e411b7a5e5267ba5a079ec78e1f367993eebdba3020db0a11', 'openubmc-debug/scripts/target_runtime_cli.py': 'eaee30d733dacb4f8d54ebac5390980dd1fe5fc902e39fd87435e255f797308d', 'openubmc-debug/scripts/target_runtime_mcp.py': 'e545deee32526eafd09c3d98e221c022d0f3a70cb36479fc7927da38f1dd8576', 'openubmc-debug/scripts/workflow_remote.py': 'f86419cdc9dff213f624331e53c12eb7db880908cbf838fecce3a0bde5168e07', 'openubmc-debug/skill.json': '488302537e674eadc16c30fc2ebdc11699ce9e1ec3b47e995a9e562e57a0e820', 'openubmc-developer/SKILL.md': '821796fe936ca30dea7519bd8249f6ec952bda3bad674a686f3bd1e533a68219', 'openubmc-developer/agents/openai.yaml': '1af2345d5b7be4d6d9c22f0501c86c4ad377e1217e5279cfac2f0478f0b825ba', 'openubmc-developer/evals/evals.json': 'ddaef44ab0aed6a2fe72025edc187db049f475168929c9e275e0a4aa0d5b505a', 'openubmc-developer/evals/trigger-evals.json': '46a9ec1f3270a901af77024c262056d183f5d5fa2a1dd160550a68c41c6846f8', 'openubmc-developer/references/development-guidelines.md': '14f0bc7ef4c6d805e76c359cda6ddc084871034eb9ffae292545aa4022a916cc', 'openubmc-developer/references/downstream-handoffs.md': 'fdf221d3abc3268336ef656c97eb8f3893d6d6b23ca8f4d61d70e1287e696049', 'openubmc-developer/references/hardware-vpd.md': '76f15601c7d2495dbe22ffb464d0ad4e1fd91533c0e0692547da359f843c8362', 'openubmc-developer/references/interface-mapping.md': '715e56261e75013a6a57d5486ef06fe83259fe31416c3c620fbc2193ecd5d092', 'openubmc-developer/references/lua-component.md': '6cb1e40d332d5dbf71a75a8f668b5cb05c4c79082ea14cf180cf6de89924a5c8', 'openubmc-developer/references/mdb-mds.md': '12d9c8909bb0b8b95d1ad4d68c0a6a83e5ed26044097e61cb454e171fb79781d', 'openubmc-developer/references/native-user-space-and-driver-abi.md': '79268d4824b23d74a742e0148a64cb32262d57f779b72218fc78e59d1626385a', 'openubmc-developer/references/persistence-compatibility.md': '93c910bc9d46c1d73365dfdc0056ceae8d490fba34cf077776ed3aa379354bb2', 'openubmc-developer/references/profile-schema-import-export.md': 'ce61783c3ad06f4cdb8bffd010830680874d3de30e7b12c78f5201ad118d301c', 'openubmc-developer/references/sr-dds-product-records.md': '6b518bead2a98c01b8a5a4634e6b8d82525ecb06564d1fd6bf2c589077e86eef', 'openubmc-developer/references/startup-product-assembly.md': '4abc2d1e20043d7c09df35f6b21e597f3b122297dc36886584f1c3c88224ec88', 'openubmc-developer/skill.json': '6fb49b2396fba98c610a62287be0c8c98864c36a2e2c6dfcff8beed765a4c294', 'openubmc-environment-setup/SKILL.md': '14747ff994b0dcf8a74bd2e078bb3356db14f2e473c08a6825b4b5902d1c1342', 'openubmc-environment-setup/agents/openai.yaml': 'b1dc43540955cdf15475b4a5ee5111b925898f9acde3d49ec5157e16dbc04272', 'openubmc-environment-setup/assets/hw_ibmc_bmcgo-0.7.51-py3-none-any.whl': 'd8424a2e8a4549ffd5d574288ed7d9016b91b2ae0d5c2463387102250795ae1e', 'openubmc-environment-setup/scripts/client_config.py': '22bd321c5a4033b7ee0338a731e9e09db2649194e2233a1715ac115e544c7435', 'openubmc-environment-setup/scripts/install_environment.py': '0af0870eac82c6a37a7899bb282eae24fd2926f7d273a98030540f3e67dd0a18', 'openubmc-environment-setup/skill.json': '36e5f480a1b3a28e1c2f233d2fcb926dac92f76fed3e4e44ca7bacb2a6f71738', 'openubmc-live-patch/SKILL.md': '81d5418e0b836ac5c64d79142cb0fd5490510cfe92b79836dcd040178c959b8c', 'openubmc-live-patch/agents/openai.yaml': '317511e53041a4923be5d55211eb43aa7456362fa7f1d3aa77923fa03fa94115', 'openubmc-live-patch/openubmc_live_patch/__init__.py': 'c1ef77736d82b012eecdfc46d1533394195673b7054f494babe6c4df7ad1581f', 'openubmc-live-patch/openubmc_live_patch/runtime_backend.py': 'dd9b8347807dd5bf5ec64f80857f2e51a8c9ef8dbe7551f10eac9f29d99efb9b', 'openubmc-live-patch/references/live-patch-contract.md': '7455c2c29b143634ee43eb104201dbb46d58e9718ca7320add61adb3974140e5', 'openubmc-live-patch/references/remote-file-patterns.md': 'a48e85281218db9751be058cc7d4e37034e53742b4998bf7011a3c787b612853', 'openubmc-live-patch/scripts/deploy_current_patch.py': '1b89ea616b33ae3d9ef8d547e66a75033fd419bc6c7a6974e517c373f34ba3da', 'openubmc-live-patch/scripts/deploy_live_file.py': 'd24ce4ba62689c605691e4f74e7ae6aba45176a14e91defd770df9536effe465', 'openubmc-live-patch/scripts/infer_live_patch.py': '2a4117dfcc759f5290575da46a5ed56ed8c99e88d05e142f77d10bf87446063b', 'openubmc-live-patch/scripts/rollback_live_file.py': 'f5e4ec5a3ba859657d370cd2a79c059c8aae9284a4e6a106b97a256554187d0a', 'openubmc-live-patch/scripts/runtime_cli.py': 'af972e8121ac4bb13f9668a1b9d219661a866c535199b3b18a00acb6696004c3', 'openubmc-live-patch/scripts/target_runtime_adapter.py': '34e9ce5fd52997fffed0ea7300517faf69c13df22e6cdd3e18b112cc227e5377', 'openubmc-live-patch/skill.json': '24dca39cf1b150bf2097a8c3438b46c5cb7200dc6646fa2a64cb0eceb1ae9468', 'openubmc-log-analyzer/SKILL.md': '679e03ecf9a7ff976cc79d71a62c4dbb0c504a8a67d81403ebddc8453e663727', 'openubmc-log-analyzer/agents/openai.yaml': '148f36bcb651b4b984e22008f6bdeb51b373b8ec9f71912a01485f57f4a5f636', 'openubmc-log-analyzer/openubmc_log_analyzer/__init__.py': '7aee28fce5bacfb4a0458faadfe242ac4f6027f528c50b13696e44d007c688ee', 'openubmc-log-analyzer/openubmc_log_analyzer/runtime_backend.py': 'c02fd4845d93f5fc5e72865cf155918d75289aea26251472ca346a505718c7e9', 'openubmc-log-analyzer/references/analysis.md': 'e69aed8f451a8180063fd70ebf2a2db7a793e26b286e2354e7aee9a458730259', 'openubmc-log-analyzer/references/logs.json': 'b9df3fd92551e5a098bf6396fbf06b768b9cd0d1c8e4cd721a315c7a2f224db8', 'openubmc-log-analyzer/references/logs.md': '46983fbff69187466de1a9acce283532adb142c4a71e2dd39c863c9b7cf22a21', 'openubmc-log-analyzer/references/remote-collection.md': 'ece24e60cd52e29f58b3ff0a2761144a3eba61281a043281f4a949673759e19a', 'openubmc-log-analyzer/scripts/_runtime_distribution.py': '17e07a13cb2d40730888191f6c6f7d9ba12b81b682195fe9b7f4aff29466207e', 'openubmc-log-analyzer/scripts/package_skill.py': 'e3b167e9906c8131bba13d23c30839331aecad016f7c27e91c406cee4c06d600', 'openubmc-log-analyzer/scripts/pull_bundle.py': '5bcd8d1a75cf7f6495b4592209cb9d52ff5de426099c852b8f517e381e620b0f', 'openubmc-log-analyzer/scripts/target_runtime_adapter.py': 'f697e2f685cecd99d108e37dd1e358244ba414d9a736c14b9e79bc11fa2f7219', 'openubmc-log-analyzer/skill.json': 'a1374a2de39288eaaac5361705b87efee977367b7b63bc9655ee11fad8bbd3b9', 'openubmc-publish/SKILL.md': 'a31bb9af83c805f6b442fc586156ebdd1def95608b52437c13f4f7ba616fd51b', 'openubmc-publish/agents/openai.yaml': 'b0c22dd5ae39fbd4cde83e35432611b2a14415453b22618bb985bc4d6e38bf3d', 'openubmc-publish/skill.json': '9b4113cbfbb8a5aca97a1dbc90a8ceaaff48aac32ddd5c2b20316e692696eed9', 'openubmc-target-runtime/SKILL.md': '4ce9249aec1392b2f6672189a0d2cd81995fdfc50915c4c5725c35aff3efc2f4', 'openubmc-target-runtime/openubmc_target_runtime/__init__.py': '6d8461658dccc229f210bc53755e0a481f6557072787668ccb3d49c10de78833', 'openubmc-target-runtime/openubmc_target_runtime/agent_gateway.py': '6c2365b54c774771c5cad503e0c898f75d78261f2788c24176e46bb5eb2cb9d4', 'openubmc-target-runtime/openubmc_target_runtime/agent_interaction.py': 'c4862b559a8e32b34dab4918ad90cad57c2332e1b70c8a5b67171ce5cfafd453', 'openubmc-target-runtime/openubmc_target_runtime/artifact_store.py': '3e6e3e511d88afde6323842ea65198aede0cad9a18dd67347c83993142205ea3', 'openubmc-target-runtime/openubmc_target_runtime/capabilities.py': '756ac5c0f5517448a79a125309dc259cce333e12bb52d3fdd08d87700841b8b5', 'openubmc-target-runtime/openubmc_target_runtime/capability.py': '88df3799b6a1faa3ac78c65aaa6b8c907ce7c4430af629e58441fb47c3dda662', 'openubmc-target-runtime/openubmc_target_runtime/catalog.py': '1a8e80d7e6fb43e3c431120e38298c42adb129a449eb61b711915d27d4a40691', 'openubmc-target-runtime/openubmc_target_runtime/closeout.py': 'c2dcefdb2f200103c79091135fa86346e7254f1582bdae4d171d8a878a2773ff', 'openubmc-target-runtime/openubmc_target_runtime/comparison_receipt.py': '308565148e93ca65e3f7eb800f915dd6dafea8668462cd49a76609efb88abd02', 'openubmc-target-runtime/openubmc_target_runtime/comparison_targets.py': '7007d6d298ce56cb645af2ca631ce281b818ea981e053a56cf2ccde43e86fecd', 'openubmc-target-runtime/openubmc_target_runtime/compatibility.py': 'e16bbb503832e8a578dc84bd447c9de8e59395b6a6f9bad6b394c6d7a51ec90b', 'openubmc-target-runtime/openubmc_target_runtime/composition.py': 'a679b7a0f25cb541205f8d5dc518f9371ad5bd07625eae1fc8ce686d6c0eeb0d', 'openubmc-target-runtime/openubmc_target_runtime/context_runtime.py': 'aa313af7c61c256c52bc81b0041f048bc6d40b7e07e542f2389305dcc665970a', 'openubmc-target-runtime/openubmc_target_runtime/contracts.py': 'dbbe5954f8a47dadc861966fbf26e2b7386cddd17e49b53273e8aba1f7a40494', 'openubmc-target-runtime/openubmc_target_runtime/credential_file.py': '8aa7100fc827eda3018a3d2a982e4f11bb8756c82c5383c453ce37343d7942c4', 'openubmc-target-runtime/openubmc_target_runtime/delivery.py': '80b9d097c993683028004a03e450c737dff8772c0252fd13d49f58e958c55dcb', 'openubmc-target-runtime/openubmc_target_runtime/diagnosis_record.py': 'd3741ce0546a97e3c55959e869b0cfd93979b58e21e51c722525b993a51a7f29', 'openubmc-target-runtime/openubmc_target_runtime/diagnostic_receipt.py': '950b0aa9026122e394233174c8edf7e4b0ade2ef6fa61ba9dd71613331fcb673', 'openubmc-target-runtime/openubmc_target_runtime/diagnostic_request.py': 'd8b529a0a01dce8cb480e2c3c46abf4ce790c29422dd78eadac7811e55a811b4', 'openubmc-target-runtime/openubmc_target_runtime/distribution.py': '6837a58ef13b91f841e0ab416ced1d700b4eebe8067ac342aeb8c1c88d14b8ce', 'openubmc-target-runtime/openubmc_target_runtime/domain_packs.py': '969e74eb37694ac776e172a4961ea58dfbee7b70bdcfe1fb812510c79d61c1dc', 'openubmc-target-runtime/openubmc_target_runtime/domain_runtime.py': '2c9bce3db6cd4f1a40162ddf6ba0b5623f566d93c141201667ba32937e2bf8df', 'openubmc-target-runtime/openubmc_target_runtime/effect_activity.py': '5962c133ce24ea91133f2a9407b43e1189c140052f1946d35318f5233bf87789', 'openubmc-target-runtime/openubmc_target_runtime/effect_runner.py': '37ffaa0de80503836ac6ed14dc0961738dfed5826e12e607a33e5298c3edc88b', 'openubmc-target-runtime/openubmc_target_runtime/evidence_store.py': '7704d29c25f13680bb204ba747ca36f4f535e0b92da1e37b6cbb1b7a1324c3c1', 'openubmc-target-runtime/openubmc_target_runtime/incident.py': '94d8d21dde176995a29ff788d4bdeb2d5eeeb25a363e6a9ed8743aba8f6b3358', 'openubmc-target-runtime/openubmc_target_runtime/lifecycle.py': '34ce024457dd2f5acfa4dcca4ac05ab3f68fcb12371d632085d2307ab3e8a192', 'openubmc-target-runtime/openubmc_target_runtime/mcp.py': '502f0a9c5c9df45e058dc9c406a7f5f647c5c1270704576f599673618f3d59fb', 'openubmc-target-runtime/openubmc_target_runtime/mcp_lifecycle.py': 'a9e1903331c6b8f50650d29de55f60fc4a214241bfbafce379a4516efe8bd0d8', 'openubmc-target-runtime/openubmc_target_runtime/mdb_query.py': '0faa17f690b13b2f6f6e47fb7d8cd88afc53547ca44ccae1ab930dad77c342f2', 'openubmc-target-runtime/openubmc_target_runtime/model_planning.py': '32d2486e88303b141aa533cb63b0acd7dbe9732948743dc93218bfc4d599f20e', 'openubmc-target-runtime/openubmc_target_runtime/mutation.py': 'eaadfaed0b32b3eacb21ea0c4132e4784830f6ab6dcf28b0b148b8a66b003d8d', 'openubmc-target-runtime/openubmc_target_runtime/observation.py': 'd6403f4713bfe2daf0f80d9bba0f42e70e69363c094f12093e55fbdab372190e', 'openubmc-target-runtime/openubmc_target_runtime/openssh.py': '67dc5fe8fc9063fa0ecd551834b2708e0e956a7c64fd04b6361b2e5d1fdff525', 'openubmc-target-runtime/openubmc_target_runtime/operation_contracts.py': '8e9004664b173e3d90045f2ce29cba39a5c451871bc960bccd01ee18efa53905', 'openubmc-target-runtime/openubmc_target_runtime/orchestration.py': 'de00d65e43f66fd3df5e4650f8fb1db40126e12ef604f2381bcc8237cf7f5e23', 'openubmc-target-runtime/openubmc_target_runtime/redaction.py': '04ddbfbcb7de4ff0e0be54df313f8d4ec9d863eb5c8fe0b1e8978dc0a90ffafb', 'openubmc-target-runtime/openubmc_target_runtime/release.py': '54ac312d600714928b27173c2ecd911f23941e18500fbeb7ca56ae62a757d629', 'openubmc-target-runtime/openubmc_target_runtime/replay.py': '008b3269fcae96454e6675977f204c183ae987138f248eaa31d70b55142fb42b', 'openubmc-target-runtime/openubmc_target_runtime/run_engine.py': '68a59201ed165d10a5cd7babfcd0442f71980016659cec23e01594ba36c94e19', 'openubmc-target-runtime/openubmc_target_runtime/run_store.py': 'b4424b8b5a1dc7a107f743a4853c717b4d09c598eea253f07bf5ace1074f0b87', 'openubmc-target-runtime/openubmc_target_runtime/runtime.py': 'f9e7b747902b92ee06d3e7553aaae8880e243dd4c42a1caf65c9ad9e935f97df', 'openubmc-target-runtime/openubmc_target_runtime/runtime_adapter.py': '9a0e506ddef921d3c6a61013de99e28e56e6ae3c77a82c2b2aa7a0277adf6ab4', 'openubmc-target-runtime/openubmc_target_runtime/scheduler.py': '3ac272419e6eb75f5ba21a7eb832a4daceb9d66fba0428f697fadc7b240fe65e', 'openubmc-target-runtime/openubmc_target_runtime/semantic_runtime.py': 'b500aeacb154bdd32c75e5b27ecbb09c7ba7755ae1efe7d6fe393c731f2ffcc3', 'openubmc-target-runtime/openubmc_target_runtime/session_outcome.py': 'd17b8922cf731e3409f552751984d09c18a53bcfbb2191f7b0a119c62648559a', 'openubmc-target-runtime/openubmc_target_runtime/task_context.py': '002b179593dd14b815916f9a1db3a10bb0c72f44cd4bd069b3429c76b271280c', 'openubmc-target-runtime/openubmc_target_runtime/telnet.py': '352ee0b2ce0007d3f670142a245506a1d7bb58f802ca7840d224384ebc695791', 'openubmc-target-runtime/openubmc_target_runtime/validation_readiness.py': 'a279e4d174e6a79ed614f346b5479490f0a9adf211cf7f442f8873ab3ca274fd', 'openubmc-target-runtime/openubmc_target_runtime/workflow.py': '53641d025ad25351aac9bcef62e69fb5307c7b6a0b9f77d0ac088a8958b168f3', 'openubmc-target-runtime/tools/benchmark_context_runtime.py': '4250342fd491b3b81fdfdf19497b6d5204f4edad6df3c387fd4638653880e943', 'openubmc-target-runtime/tools/package_runtime_skill.py': '0a813a0aeabf3a531ef3853907d6e6665c9882f74ded32148a871e662e8f9dc9', 'openubmc-target-runtime/tools/runtime_loader.py': '29e995cec5032850a48886832684319b13655f7ee7f81d6f4d693f6db9000ee3', 'openubmc-target-runtime/tools/smoke_debug_context.py': '251dc2c666ba89de9bffb6b5e49fa3790085881a2f09d99e332452c997b9c03c', 'openubmc-upgrade/SKILL.md': 'd77d570ede1d583b95c75e379d90b226d21d7071ec1ca929d2a1e757be782c24', 'openubmc-upgrade/agents/openai.yaml': '53cb74381a5d432b62ad00678a867b08763bc3056a0122a8a8c1909c046083cd', 'openubmc-upgrade/openubmc_upgrade/__init__.py': 'd1205b7fbb71e1da441fb53d6aeaf9a6ee260bc4decde837dbd48488b231d474', 'openubmc-upgrade/openubmc_upgrade/operation_state.py': 'ee7749862f212dc8816bd3a404e957c551787e7882662945f7047b18469de971', 'openubmc-upgrade/openubmc_upgrade/runtime_backend.py': '6abce018932d21b7322e4f2ebac48aa8b54ed6a613bb20060dcbaea4899622e4', 'openubmc-upgrade/openubmc_upgrade/webui.py': 'b15602181689f9882d13ded099659347cffd4399852f691eca45916ba62a0756', 'openubmc-upgrade/references/redfish-upgrade.md': '57ccfc7b46b30afbf59614e5c092be33738c3875f1d7a33a53be93821216beb6', 'openubmc-upgrade/references/webui-upgrade.md': '46c78f0cf4e26341ce89022dd25dfcb462bccd762d1d09ddce6cdf041978a951', 'openubmc-upgrade/scripts/artifact_identity.py': 'eaa91a5243802307b5c282b5977f92cef4bcee95df95b56b4e939d7c1cc92217', 'openubmc-upgrade/scripts/preflight_upgrade.py': '1324947539a32967febb0cd3d335c57c343dda7a65a28ef82ac4c46f13f2134d', 'openubmc-upgrade/scripts/redfish_credentials.py': '5464a7a246faad7a63361d7046845f9aae3bb803721f93ffcf5179402a483e3e', 'openubmc-upgrade/scripts/target_runtime_adapter.py': '66d645e09565d5d46387628a57490706afc31daac5b6343acb3c93cd2a3938b5', 'openubmc-upgrade/skill.json': 'eab1e72aaaa528d452969768d29a3553cf732493a448e6dcceaa9149388a9753', 'qemu-testing/SKILL.md': 'd575f68ba49337b8585ebf66a95bc005231e6040b562d25dc01ceb4404ee9d16', 'qemu-testing/agents/openai.yaml': '2347231164076a1bc183947a74f92edf0771d2b27251066767208eccfe5a0209', 'qemu-testing/references/qemu-verification.md': '22b5b1bec6db19f901e423f02d04b08ed055edf32cc37e9dff5d4346f482272e', 'qemu-testing/skill.json': '412db8eabe71aac71c92f8c64c5504be1118cfb724ebca3be328033803a859d4', 'testing/SKILL.md': '93662632203524968af5c0868e4fefe8dbcf0b3d9cf0747b9f38f41a8eac00e9', 'testing/agents/openai.yaml': '43897decfaec6d3d59f14e9d6da917eae35e3d23d48174c70ed57969c5782439', 'testing/evals/evals.json': '4acbbf08e1057639c1fae8061e30da258a17ea9d7f036f6e4a0deaba89087690', 'testing/skill.json': '00f42eb9a7d2dbbcaedd9ecfbc97a99cadbf7cdbe366a8df03200d8879420d4a'}
COMPOSITION_ROOTS = ('openubmc-target-runtime', 'openubmc-environment-setup', 'openubmc-debug', 'openubmc-log-analyzer', 'openubmc-developer', 'openubmc-build', 'openubmc-upgrade', 'openubmc-live-patch', 'testing', 'openubmc-publish', 'lua-component', 'qemu-testing')
SOURCE_COMMIT = "505975a933afe28572df6ab43e3f1138624850f1"
DIGEST_DOMAIN = b"openubmc-target-runtime-content-v1\0"
RUNTIME_CONTENT = {}
ENTRYPOINT_CONTENT = b""


def fail(reason: str) -> None:
    raise SystemExit(
        "Target Runtime installation validation failed before remote execution: "
        + reason
        + "; run openubmc-environment-setup repair"
    )


def runtime_api() -> str:
    contracts = PACKAGE_ROOT / "contracts.py"
    try:
        tree = ast.parse(contracts.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        fail("Runtime API metadata is missing or invalid")
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == "RUNTIME_API_VERSION" for target in targets):
            return value.value
    fail("Runtime API constant is missing")


def runtime_digest() -> str:
    if not PACKAGE_ROOT.is_dir() or not (PACKAGE_ROOT / "__init__.py").is_file():
        fail("Runtime package is missing")
    digest = hashlib.sha256(DIGEST_DOMAIN)
    for path in PACKAGE_ROOT.rglob("*"):
        relative = path.relative_to(PACKAGE_ROOT)
        if "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            fail("Runtime package contains a symbolic link")
        if path.is_file() and path.suffix in {".pyc", ".pyo", ".so", ".pyd", ".dll"}:
            fail("Runtime package contains an unbound executable: " + str(relative))
    files = [
        path for path in sorted(PACKAGE_ROOT.rglob("*.py"))
        if "__pycache__" not in path.relative_to(PACKAGE_ROOT).parts
    ]
    if not files:
        fail("Runtime package contains no Python sources")
    for path in files:
        if path.is_symlink() or not path.is_file():
            fail("Runtime package contains an invalid source path")
        relative = path.relative_to(PACKAGE_ROOT).as_posix().encode("utf-8")
        content = path.read_bytes()
        RUNTIME_CONTENT[path.relative_to(PACKAGE_ROOT).as_posix()] = content
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return "sha256:" + digest.hexdigest()


def entrypoint_digest() -> str:
    global ENTRYPOINT_CONTENT
    if MCP_ENTRYPOINT.is_symlink() or not MCP_ENTRYPOINT.is_file():
        fail("MCP entrypoint is missing")
    digest = hashlib.sha256(b"openubmc-mcp-entrypoint-v1\0")
    relative = MCP_ENTRYPOINT.name.encode("utf-8")
    content = MCP_ENTRYPOINT.read_bytes()
    ENTRYPOINT_CONTENT = content
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
    return "sha256:" + digest.hexdigest()


if runtime_api() != EXPECTED_API:
    fail("Runtime API mismatch")
if runtime_digest() != EXPECTED_DIGEST:
    fail("Runtime content digest mismatch")
actual_entrypoint_digest = entrypoint_digest()
if EXPECTED_ENTRYPOINT_DIGEST != "planned" and actual_entrypoint_digest != EXPECTED_ENTRYPOINT_DIGEST:
    fail("MCP entrypoint content digest mismatch")
actual_composition = {}
composition_content = {}
for name in COMPOSITION_ROOTS:
    root = COMPOSITION_SOURCE / name
    if root.is_symlink():
        fail("Runtime composition contains a symlink: " + name)
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(COMPOSITION_SOURCE)
        if {"__pycache__", "tests", "node_modules", ".git"}.intersection(relative.parts):
            continue
        if path.is_symlink():
            fail("Runtime composition contains a symlink: " + str(relative))
        if path.is_file():
            content = path.read_bytes()
            composition_content[relative.as_posix()] = content
            actual_composition[relative.as_posix()] = hashlib.sha256(content).hexdigest()
if actual_composition != COMPOSITION_FILES:
    changed = sorted(key for key in set(actual_composition) | set(COMPOSITION_FILES)
                     if actual_composition.get(key) != COMPOSITION_FILES.get(key))
    fail("Runtime composition mismatch: " + ", ".join(changed[:8]))

# Execute only the exact bytes that passed the checks above. Helpers loaded
# later by path or subprocess must use the same snapshot as the MCP entrypoint.
# Re-reading the original paths after validation would reopen a drift window.
_composition_snapshot = tempfile.TemporaryDirectory(prefix="openubmc-runtime-composition-")
snapshot_root = Path(_composition_snapshot.name)
for relative, content in composition_content.items():
    destination = snapshot_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    destination.chmod(0o500)
snapshot_package = snapshot_root / "installed-runtime" / "openubmc_target_runtime"
for relative, content in RUNTIME_CONTENT.items():
    destination = snapshot_package / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    destination.chmod(0o400)
try:
    entrypoint_relative = MCP_ENTRYPOINT.relative_to(COMPOSITION_SOURCE)
except ValueError:
    entrypoint_relative = Path("entrypoint") / MCP_ENTRYPOINT.name
snapshot_entrypoint = snapshot_root / entrypoint_relative
snapshot_entrypoint.parent.mkdir(parents=True, exist_ok=True)
if snapshot_entrypoint.exists():
    if snapshot_entrypoint.read_bytes() != ENTRYPOINT_CONTENT:
        fail("MCP entrypoint changed during composition validation")
else:
    snapshot_entrypoint.write_bytes(ENTRYPOINT_CONTENT)
snapshot_entrypoint.chmod(0o400)
PACKAGE_ROOT = snapshot_package
MCP_ENTRYPOINT = snapshot_entrypoint

# Never import stale sourceless bytecode from a release source tree.
sys.dont_write_bytecode = True
_fresh_pycache_root = tempfile.TemporaryDirectory(prefix="openubmc-runtime-pycache-")
sys.pycache_prefix = _fresh_pycache_root.name

os.environ["OPENUBMC_MCP_SOURCE_COMMIT"] = SOURCE_COMMIT

config_root = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
credentials = config_root / "openubmc" / "credentials.env"
if credentials.is_file():
    os.environ.setdefault("OPENUBMC_CREDENTIALS_FILE", str(credentials))
sys.path.insert(0, str(PACKAGE_ROOT.parent))
sys.path.insert(0, str(MCP_ENTRYPOINT.parent))
runpy.run_path(str(MCP_ENTRYPOINT), run_name="__main__")
