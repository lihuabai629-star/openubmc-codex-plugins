#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / 'skills/openubmc-target-runtime/openubmc_target_runtime'
MCP_ENTRYPOINT = Path(__file__).resolve().parents[1] / 'skills/openubmc-debug/scripts/target_runtime_mcp.py'
EXPECTED_API = "openubmc.target-runtime.v1"
EXPECTED_DIGEST = "sha256:5daa97a861b1a48c17a87647a6edf3ae967e7dcd229c889080ab5c7c5c522ff8"
EXPECTED_ENTRYPOINT_DIGEST = "sha256:bf3f9a11dd8f38724771af66a5361eb6258e3eb2354a6cfbba072b8977cc4308"
COMPOSITION_SOURCE = Path(__file__).resolve().parents[1] / 'skills'
COMPOSITION_FILES = {'lua-component/SKILL.md': '16fa78b8ca9f127134758d7b6999a53ecaa2137c240f7f85fc6ee712152c8b67', 'lua-component/agents/openai.yaml': '08dc82afd1e8d0e14ccd1cedfaa9a5e5d23a320f8a8bfd9f24669092ebed2a63', 'lua-component/skill.json': '80bf5c44b4aaf2868cc9013093b5a5809b9f758027505465d9d62eab8e80ba58', 'openubmc-build/SKILL.md': '4200156e9e4561ad666bcc8818e3ab433e9ef26e151b8fd4166d72e4857f5479', 'openubmc-build/agents/openai.yaml': '9fa2ad6d3de4a79b2bac163765bb0d7a4cc0ae956b35c6b0dc9158cc2bb7f17e', 'openubmc-build/references/2630-wsl-profile.md': '55f47c5efde498dc6f82022c108dad5085b5ff1cff8769b73cc51e7d2cb1b3d5', 'openubmc-build/references/artifact-verification.md': '1356317d109410b23e59037b2afd8202001a1b6280edbdd6420cffc59a800e88', 'openubmc-build/references/build-plan.md': '3f42ff91b9a161ce25f7b77c301553268bb8e67115d1ead4fba7fc098ee06a23', 'openubmc-build/references/conan-auth.md': '282f6d32a1055df0e609a2e81a9e028762b3935218dd1599d04d05337670c46f', 'openubmc-build/references/handoff-contract.md': 'cc9d3ff9ea53b293d371546d4d20cbfd6faafd976db2f0ccc6496aa6521493ec', 'openubmc-build/references/modes/component-package.md': 'f66fee6fd5e6d56c8780e4613bd5e008634bbe0444043efabb6e7083d1ed999c', 'openubmc-build/references/modes/diagnose.md': '9cee2e5daa8885f5c9378acb6e5edda3c1ea2f321c54c7064445b158594d9e07', 'openubmc-build/references/modes/product-artifact.md': 'f6f8fd4e2dafd1b0633d0177ca0bee962eb98437a79c7a852ebe4caee19865a9', 'openubmc-build/references/modes/publish.md': '5e830c25953d2ae9c92f07c354ed30c4692719186189660679dde4ac91f5ddea', 'openubmc-build/references/modes/validate.md': 'e447d40bc19b9f19312d387499bbd8f0bbca3e267615df07906789a86ee268a7', 'openubmc-build/references/product-build-pitfalls.md': 'fc7c960448bc6e008db49ee77e3ecc3e81b54f62cec87ae89e2d154deb56dfc2', 'openubmc-build/references/redfish-upgrade.md': '7677bdeeae87a060a7496687d027ef30b3ff379c4cc07cf148b0e4ecebe04b24', 'openubmc-build/requirements-containment.txt': '6826a8358c3fbc21c12fd74cd83771ea62cf83b07be2712ce1aa3da284ae67ab', 'openubmc-build/scripts/check_dependency_delta.py': 'e7f730a456979809b2369dd8da7c14fab9181b178f56b997e5cbcc6b655f2dd0', 'openubmc-build/scripts/check_rootfs_access.py': '308bd3f484b3367cc4bd985276662ae8981bef4f9cf6bd9b47c01dac23ccf607', 'openubmc-build/scripts/completed_evidence.py': '5e97d5481282ba703b442d2bfd6c7b5293adabaaffa9e39cac0c65d2985f5fdd', 'openubmc-build/scripts/component_impact.py': 'df2f5e89a2f29a4492d74a948b8dcc1de615072dbf59f4c1898c9eeccd8f3dd9', 'openubmc-build/scripts/create_build_plan.py': '8ec7328e90ebf80c78736463d85c3c74598650a9d6118adb05f2a45af35b4e8b', 'openubmc-build/scripts/detect_changed_components.py': 'cdc402415e3bf7b606d2576a8fc00c8660afc9d2f5106f1d827d35b9942ede93', 'openubmc-build/scripts/ensure_planned_version.py': 'fc25781c4d9a53d07c83a94eeb0ee414773e5db2fa0d519ab38014e57ddd88b5', 'openubmc-build/scripts/finalize_product_attempt.py': '0282f6a4be2441e334b09929ab04c061b69258702192eea560444c9da0a19e71', 'openubmc-build/scripts/preflight_build_env.sh': 'c0e8c43d604de36919a98f10dba5ea093f47ef5b1680816444d2f6cce76e8d6c', 'openubmc-build/scripts/run_bmcgo_checked.py': '5434c1b8cd85a870b8132d72a86664ad6fb225047c45ae9d59c6d615b8de40cc', 'openubmc-build/scripts/run_build_attempt.py': 'cc408f415bf0c6844d4b0fa7b8ec25a3e80ea7121bbad2094529a0de3b3816ce', 'openubmc-build/scripts/update_manifest_conan_ref.py': '9650349dab65e7a9465b2f125e09eb9177a3b1255029bbed64f2fcded2f5842f', 'openubmc-build/scripts/verify_hpm_containment.py': '66dac0a4f723ac28901f40e16a72f3ab81758e9518384261b5b2e5dca0fd69e7', 'openubmc-build/scripts/verify_product_artifact.py': '5b570e95b161f5ff570baa97209d678b75309f884ec05dd54db7e1df742ae702', 'openubmc-build/scripts/write_artifact_metadata.py': '5206725ac0609f739e52a929d1544b5f6cfa8012bb5edf122e02ac6d57ab05cb', 'openubmc-build/skill.json': '90a3417a18e18fedfb12ef3e2d9ac09184bc7f01bf3c1fccb99a956c0fd067c8', 'openubmc-debug/SKILL.md': '7c351399ee6d23a66f6ea02dc28db2357d066e163446a162f8718a61de112418', 'openubmc-debug/agents/openai.yaml': 'ad7d59367eb9abfd743d205d89066d0e96c88fb426978a2a29999407d7f81c34', 'openubmc-debug/references/agent-gateway.md': '8424792dd7e31e7928490debbd605b9a409fbbcdd14177f79a99b46e258448e6', 'openubmc-debug/references/alarm-access.md': 'fdf6ea9e5d52f2fd3af7b55fb311e4c5f794c0c7e0f74389af88b430ae067e49', 'openubmc-debug/references/busctl-access.md': '7e08711311545e414865669a721f03629316a5ab37e9779a45d18a75df7fc0b6', 'openubmc-debug/references/components.md': '013327abb03a501bbc1678e912e482297cf26a9069323067d80590d8debd2457', 'openubmc-debug/references/diagnostic-advice.md': '92f1de5e4fa7ae60928a5639da3e5c5f78bdddf0a20b74c57a617c4a94f99c6b', 'openubmc-debug/references/diagnostic-contract.md': '84b54f86259347ec1487b8bf548282e2cd437f85bf89a0d768845233d472c296', 'openubmc-debug/references/evidence-workflow.md': 'd9a7c11e90bd3dcfafaee074eaf88ddd4e5a4c93c6a5b7f30a6c7a30f90f6288', 'openubmc-debug/references/file-access.md': '5041b5a16acb4c40bee95932d84fde219d29e49198f8cac3b2a754c45933ed60', 'openubmc-debug/references/knowledge-routing.md': 'a49898fd45fd2f77c7fc8b776426d942c6c9ec597d97a3a8278ed403ffbaf935', 'openubmc-debug/references/logs.md': '334204de8c0febbf6c13c0b6dbd69ea032977ca4e95b025c2bcba3368de7d7ca', 'openubmc-debug/references/mdbctl-access.md': 'c1d212dd685ef955b9dd3d24a5be77e5757020a5681693f92f58f2fe4d4217f6', 'openubmc-debug/references/mechanism-debugging.md': '20451665cdea13517fe2482621a1fdd7010659eeb6701ccbaad2ec06a17d7fbd', 'openubmc-debug/references/object-access.md': '815d330e52822e6d6e6e914a2e8e7cf21ab60d3149a4d8eca1e054a12845a2b0', 'openubmc-debug/references/openubmc-debug-compare-v1.schema.json': '4312dc23c506e4b426cbab1445f9cab317cfd8e04f5f3bc5a5d75b2a1e8d72e9', 'openubmc-debug/references/optional-integrations.md': '4537c7dad1d53a9548fee324a64d25f8506cbbeeb619e0ca2685aa6d288eeb39', 'openubmc-debug/references/remote-automation.md': '8123554555429e5fefd9c12806a34a46b4a40d57d7608a0bdb97f6779e4bb349', 'openubmc-debug/references/workflow.md': 'bd443de69dc047445f4e14bf9ee4530f8fa1e8a8622db10851b27f330f9df403', 'openubmc-debug/scripts/_cli_common.py': 'c8ef48f5e7936611bdaaec51ecfcdd505f95172216fa0be9f405c963ef6249f6', 'openubmc-debug/scripts/_comparison.py': 'adbe2e6946da5982b74065b50a5b9f49c0f206bb605b4ff984a605ea258a0365', 'openubmc-debug/scripts/_debug_dump.py': 'd62f7d5d5a4b7bed479f9d8aef92448fa918a8efbc0f330a932b1d5d1a13457e', 'openubmc-debug/scripts/_json_common.py': '25270e20f31c8f3f8d5762d08194299f7af52afdc15eb3a72331b3fbc0510b9a', 'openubmc-debug/scripts/_minimal_telnet.py': '3134df03634b8f8c600b00da7085c8291032864d2aceffab1fd63142b42dae98', 'openubmc-debug/scripts/_plugin_entrypoint.py': '574212f81248bedffc9e9eab01f6c2f7b01a4eda7dae7f58ea17828cbb3c4218', 'openubmc-debug/scripts/_preflight_checks.py': 'ca7124ab8fccf6d97d798480af4200005f77c9bbc734e3e1b265ca2e3f226505', 'openubmc-debug/scripts/_preflight_recommendations.py': 'a55311f94ae8bac99a69189e95f6520336102355700d35666cc831cc2079a97f', 'openubmc-debug/scripts/_remote_common.py': 'b0e6f43ba4e3baae2c1259ccb35c2f9efcd423f84254b99055954d36ae631fd0', 'openubmc-debug/scripts/_runtime_distribution.py': 'e826e27173cfb40f8177fc280a0cfe9a36442e69018428761da37f374b6cd17b', 'openubmc-debug/scripts/_source_root.py': 'cebc7277650c3676d0b263fee6a885c9d94ba7be18fec40cd2550190fa35648a', 'openubmc-debug/scripts/_target_runtime_adapter.py': '5a3bb509e0c8976cf534c3d65a8f506179976ee3f887ffaea9d2a975bdc10620', 'openubmc-debug/scripts/_telnet_common.py': '4c4613c070f7e31c7c52cc7016fc2c7ce024110ef1685390532137ed3cfcf0c9', 'openubmc-debug/scripts/_workflow_contracts.py': '824bc12a457c2aca846ea194f2ef864d542b701e5bf4fb04eaf547f101eedab6', 'openubmc-debug/scripts/_workflow_correlation.py': '7b84ea4e9c50f1501bb5c00ce1d0b5aad06ae96f5180b7f73eadcc4851c7e48e', 'openubmc-debug/scripts/_workflow_freshness.py': '41db861161a670b779cc6adab437c189940cec9d2b7f31b6ad72ccd015336b75', 'openubmc-debug/scripts/_workflow_runtime.py': '698b05e16dd868827c6714e4559ac08b3e169461b6d77356fa697e1490fcd379', 'openubmc-debug/scripts/_workflow_source.py': 'f80d19001fcdf7bd28a8c28729873698f14c28c27413f08b9c95e9f1e435a906', 'openubmc-debug/scripts/active_alarms.py': 'e47d8989e09fc169ca8b206db1d2747647443a6f6d60bb623dae5f10dddea348', 'openubmc-debug/scripts/busctl_remote.py': '61f837ffec600af14352c9ea64558b04143e5e1b608a93105b99a1401cd826fd', 'openubmc-debug/scripts/collect_logs.py': '66ef21b869dbd11c547054d947a43c420ea5d021400a3ff2d91f350829b148c0', 'openubmc-debug/scripts/compare_remote.py': '194e80c72a98bec756e711463bd3ba0c75f0f8b8e7bc2d2261008d207e8753d2', 'openubmc-debug/scripts/diagnostic_advice.py': '605119d61f12d7bb2640dbde03cb5219d58a24e708d46518f29f791eb8b60bc8', 'openubmc-debug/scripts/doctor.py': '9b604947bd315b7ef9ac29dfa7ac501fa148b2efaaf0e6e250c1c3a579b61d76', 'openubmc-debug/scripts/mdbctl_remote.py': '31e8efbed8b07a57362849884d5cbbcbb7f6444498cb10a5d81981fd9c9e0a65', 'openubmc-debug/scripts/package_skill.py': '5a583ae401b049a9ba10f2b4ecea778d981bf271446640a93d530eb54c4b464b', 'openubmc-debug/scripts/preflight_checks.py': '34dd59abceddca4864c63f645823e725ea8463bc81e72006ae5537368904f838', 'openubmc-debug/scripts/preflight_recommendations.py': '2cf9e59196fcdfc03ea6f2baab1bb278e5fc56fd2c971781fc459d552c73b2a1', 'openubmc-debug/scripts/preflight_remote.py': '73e60557484628904083f3c0328d9a54d1d0433776eb721ed31c65fb0ed017df', 'openubmc-debug/scripts/read_remote_file.py': '47e12ac5b3c9e92d785ff4c5d5af69274e3cea5373b6f4f90620ccc5d58e0b9d', 'openubmc-debug/scripts/source_trace.py': '04dbff8ed2aeaa95624bceed2b731531c7a101ab08861539f077afd100025e15', 'openubmc-debug/scripts/systemd_observation.py': 'f9cee3e3b377e229fed589cdc4d1c67fd7ded25bd79bbc19d17fd454c794406f', 'openubmc-debug/scripts/target_runtime_cli.py': '779fee2086e2ebb46499aba58e3978c5f405f2f9cc09ca494939eba373b2548d', 'openubmc-debug/scripts/target_runtime_mcp.py': '80cd5d6355bbccac35869dee6d5eb6c7cc39f88367df790fd3f0ddce08624758', 'openubmc-debug/scripts/workflow_remote.py': 'af1b6ca217fb50bb77038e979bc2a031ca75e74a4ed985463f35d63ba90c1ab3', 'openubmc-debug/skill.json': '8011f5a362d2275bc5fee21ee2f998efdc2a4e5ee639bbae51d4b5ccf17ddfaa', 'openubmc-developer/SKILL.md': '14b10394d0951961ca78ce62f5c1651a19c740cbdacfbab14a9dd3cd079991e8', 'openubmc-developer/agents/openai.yaml': '1af2345d5b7be4d6d9c22f0501c86c4ad377e1217e5279cfac2f0478f0b825ba', 'openubmc-developer/evals/evals.json': 'ddaef44ab0aed6a2fe72025edc187db049f475168929c9e275e0a4aa0d5b505a', 'openubmc-developer/evals/trigger-evals.json': '46a9ec1f3270a901af77024c262056d183f5d5fa2a1dd160550a68c41c6846f8', 'openubmc-developer/references/development-guidelines.md': '14f0bc7ef4c6d805e76c359cda6ddc084871034eb9ffae292545aa4022a916cc', 'openubmc-developer/references/downstream-handoffs.md': 'fdf221d3abc3268336ef656c97eb8f3893d6d6b23ca8f4d61d70e1287e696049', 'openubmc-developer/references/hardware-vpd.md': '76f15601c7d2495dbe22ffb464d0ad4e1fd91533c0e0692547da359f843c8362', 'openubmc-developer/references/interface-mapping.md': '715e56261e75013a6a57d5486ef06fe83259fe31416c3c620fbc2193ecd5d092', 'openubmc-developer/references/lua-component.md': '6cb1e40d332d5dbf71a75a8f668b5cb05c4c79082ea14cf180cf6de89924a5c8', 'openubmc-developer/references/mdb-mds.md': '12d9c8909bb0b8b95d1ad4d68c0a6a83e5ed26044097e61cb454e171fb79781d', 'openubmc-developer/references/native-user-space-and-driver-abi.md': '79268d4824b23d74a742e0148a64cb32262d57f779b72218fc78e59d1626385a', 'openubmc-developer/references/persistence-compatibility.md': '93c910bc9d46c1d73365dfdc0056ceae8d490fba34cf077776ed3aa379354bb2', 'openubmc-developer/references/profile-schema-import-export.md': 'ce61783c3ad06f4cdb8bffd010830680874d3de30e7b12c78f5201ad118d301c', 'openubmc-developer/references/sr-dds-product-records.md': '6b518bead2a98c01b8a5a4634e6b8d82525ecb06564d1fd6bf2c589077e86eef', 'openubmc-developer/references/startup-product-assembly.md': '4abc2d1e20043d7c09df35f6b21e597f3b122297dc36886584f1c3c88224ec88', 'openubmc-developer/skill.json': '6fb49b2396fba98c610a62287be0c8c98864c36a2e2c6dfcff8beed765a4c294', 'openubmc-environment-setup/SKILL.md': 'a670e0fc67732a13a95ef849da4f358da2594df3eb4aceba5ad6ec210b8f2771', 'openubmc-environment-setup/agents/openai.yaml': 'b1dc43540955cdf15475b4a5ee5111b925898f9acde3d49ec5157e16dbc04272', 'openubmc-environment-setup/assets/config-page/index.html': '69019188dc81e2226e00460ef730a7b9a9d7ace55c9c432ce57a64b389aa164a', 'openubmc-environment-setup/assets/config-page/page.css': '94fc0c5978b51b809aa632f651d88e4c700ef8bc281aa86678e794d7a89d46d7', 'openubmc-environment-setup/assets/config-page/page.js': '61c4de65020a1c8c7ec7f2f2f4a042cbbf281f7dbabb5914154fb889dbc6b366', 'openubmc-environment-setup/assets/hw_ibmc_bmcgo-0.7.51-py3-none-any.whl': 'd8424a2e8a4549ffd5d574288ed7d9016b91b2ae0d5c2463387102250795ae1e', 'openubmc-environment-setup/scripts/client_config.py': '3b6ebe5a28d49d5aef90b0fe3d1a1b43b07de01972a762e6b9bfc1548f128e1f', 'openubmc-environment-setup/scripts/config_checks.py': '8e908402f4b60ab14459ef0c685a952ac42048fa00231e3688b32b05e01b3fd8', 'openubmc-environment-setup/scripts/config_page.py': '5a061b7b09c159f8c43a0c48eb743df2a94acdba6dbf48942b5330b6bb024052', 'openubmc-environment-setup/scripts/install_environment.py': 'b2b0a72069b810494bebdb0e735e2e417ab1a253c2868d3b9d9a8824c7d45ba6', 'openubmc-environment-setup/skill.json': 'db053521dc301066a490e372eed27c442f3900f92b839d941534981965b6c265', 'openubmc-live-patch/SKILL.md': '81d5418e0b836ac5c64d79142cb0fd5490510cfe92b79836dcd040178c959b8c', 'openubmc-live-patch/agents/openai.yaml': '317511e53041a4923be5d55211eb43aa7456362fa7f1d3aa77923fa03fa94115', 'openubmc-live-patch/openubmc_live_patch/__init__.py': 'c1ef77736d82b012eecdfc46d1533394195673b7054f494babe6c4df7ad1581f', 'openubmc-live-patch/openubmc_live_patch/runtime_backend.py': '5f1eeeaf5dc764ef2a603da20405b38e2d59f106d320cdbc96957f508a5b8498', 'openubmc-live-patch/references/live-patch-contract.md': '7455c2c29b143634ee43eb104201dbb46d58e9718ca7320add61adb3974140e5', 'openubmc-live-patch/references/remote-file-patterns.md': 'a48e85281218db9751be058cc7d4e37034e53742b4998bf7011a3c787b612853', 'openubmc-live-patch/scripts/deploy_current_patch.py': 'a228e84f6422d5bcb2de259d7dfe32808ce0e77188befdec4502bc925fde1669', 'openubmc-live-patch/scripts/deploy_live_file.py': '3eef5168fa7becfc4ffb7f0f484c3d184c3cf09ce89c7c9f93aaefd62e768979', 'openubmc-live-patch/scripts/infer_live_patch.py': '5145ce5bf0e1c46e5d884d7104e624a07b163f0e3996bfcb4264ddb1eaacd0a3', 'openubmc-live-patch/scripts/rollback_live_file.py': '3820e6fa4244886b009fad9da0adeb8fc00bf79f49dd1bd63f4acc19c2b4ecc7', 'openubmc-live-patch/scripts/runtime_cli.py': '089bbb0d130c2160a995a6988d84bda5817fcca7a1f4dc2453399ffe696f339e', 'openubmc-live-patch/scripts/target_runtime_adapter.py': '3364d1949e2d6531c9bd549ae9e0630d60299c7c4f4c667c3f8b86da32ce8498', 'openubmc-live-patch/skill.json': '24dca39cf1b150bf2097a8c3438b46c5cb7200dc6646fa2a64cb0eceb1ae9468', 'openubmc-log-analyzer/SKILL.md': '679e03ecf9a7ff976cc79d71a62c4dbb0c504a8a67d81403ebddc8453e663727', 'openubmc-log-analyzer/agents/openai.yaml': '148f36bcb651b4b984e22008f6bdeb51b373b8ec9f71912a01485f57f4a5f636', 'openubmc-log-analyzer/openubmc_log_analyzer/__init__.py': '7aee28fce5bacfb4a0458faadfe242ac4f6027f528c50b13696e44d007c688ee', 'openubmc-log-analyzer/openubmc_log_analyzer/runtime_backend.py': '0c6f65836d44a93774d42379add5111cfdc0d4979da1bea8f59ae7c241f3aa1b', 'openubmc-log-analyzer/references/analysis.md': '2d558b3498f4c76746b8a121866a9d0d873139945be3c9a9b04023c0d9353697', 'openubmc-log-analyzer/references/logs.json': 'b9df3fd92551e5a098bf6396fbf06b768b9cd0d1c8e4cd721a315c7a2f224db8', 'openubmc-log-analyzer/references/logs.md': '46983fbff69187466de1a9acce283532adb142c4a71e2dd39c863c9b7cf22a21', 'openubmc-log-analyzer/references/remote-collection.md': 'ece24e60cd52e29f58b3ff0a2761144a3eba61281a043281f4a949673759e19a', 'openubmc-log-analyzer/scripts/_runtime_distribution.py': '17e07a13cb2d40730888191f6c6f7d9ba12b81b682195fe9b7f4aff29466207e', 'openubmc-log-analyzer/scripts/package_skill.py': 'f76682ea9c5d6a90c4fcb1869ded70f6c55158191e9bc7fa7ae30380b941d673', 'openubmc-log-analyzer/scripts/pull_bundle.py': '25ca9a4cd9476ee64cae3d27324cae51014405338c004896941c62477d5299ca', 'openubmc-log-analyzer/scripts/target_runtime_adapter.py': '87ae44c365adaced9145927e9ef333c0e4f6f2a5035617dd3db4e56ef9263e96', 'openubmc-log-analyzer/skill.json': 'a1374a2de39288eaaac5361705b87efee977367b7b63bc9655ee11fad8bbd3b9', 'openubmc-publish/SKILL.md': 'a31bb9af83c805f6b442fc586156ebdd1def95608b52437c13f4f7ba616fd51b', 'openubmc-publish/agents/openai.yaml': 'b0c22dd5ae39fbd4cde83e35432611b2a14415453b22618bb985bc4d6e38bf3d', 'openubmc-publish/skill.json': '9b4113cbfbb8a5aca97a1dbc90a8ceaaff48aac32ddd5c2b20316e692696eed9', 'openubmc-target-runtime/SKILL.md': '4ce9249aec1392b2f6672189a0d2cd81995fdfc50915c4c5725c35aff3efc2f4', 'openubmc-target-runtime/openubmc_target_runtime/__init__.py': '03cf9500e41364342bc0b7e0cdcab44c289fa9497a1a456c25e9e2d4efc9a731', 'openubmc-target-runtime/openubmc_target_runtime/agent_gateway.py': 'a039ecc9c802c50420c89b2f9017406f76eb88912e31cd5729d3562a98d21b26', 'openubmc-target-runtime/openubmc_target_runtime/agent_interaction.py': 'c4862b559a8e32b34dab4918ad90cad57c2332e1b70c8a5b67171ce5cfafd453', 'openubmc-target-runtime/openubmc_target_runtime/artifact_store.py': '3e6e3e511d88afde6323842ea65198aede0cad9a18dd67347c83993142205ea3', 'openubmc-target-runtime/openubmc_target_runtime/capabilities.py': '756ac5c0f5517448a79a125309dc259cce333e12bb52d3fdd08d87700841b8b5', 'openubmc-target-runtime/openubmc_target_runtime/capability.py': '88df3799b6a1faa3ac78c65aaa6b8c907ce7c4430af629e58441fb47c3dda662', 'openubmc-target-runtime/openubmc_target_runtime/catalog.py': '1a8e80d7e6fb43e3c431120e38298c42adb129a449eb61b711915d27d4a40691', 'openubmc-target-runtime/openubmc_target_runtime/closeout.py': 'c2dcefdb2f200103c79091135fa86346e7254f1582bdae4d171d8a878a2773ff', 'openubmc-target-runtime/openubmc_target_runtime/comparison_receipt.py': '308565148e93ca65e3f7eb800f915dd6dafea8668462cd49a76609efb88abd02', 'openubmc-target-runtime/openubmc_target_runtime/comparison_targets.py': '7007d6d298ce56cb645af2ca631ce281b818ea981e053a56cf2ccde43e86fecd', 'openubmc-target-runtime/openubmc_target_runtime/compatibility.py': 'e16bbb503832e8a578dc84bd447c9de8e59395b6a6f9bad6b394c6d7a51ec90b', 'openubmc-target-runtime/openubmc_target_runtime/component_validation.py': 'eaaef92bb548ef9a325728247940fce5df4e94635671dba12cbf3c005bb1381b', 'openubmc-target-runtime/openubmc_target_runtime/composition.py': 'a679b7a0f25cb541205f8d5dc518f9371ad5bd07625eae1fc8ce686d6c0eeb0d', 'openubmc-target-runtime/openubmc_target_runtime/configuration.py': 'f3251295e51fe2978972a27de3a41d466faacf7a258c4d25af4b32603b476c1e', 'openubmc-target-runtime/openubmc_target_runtime/context_runtime.py': 'aa313af7c61c256c52bc81b0041f048bc6d40b7e07e542f2389305dcc665970a', 'openubmc-target-runtime/openubmc_target_runtime/contracts.py': 'a01c86cdd4c5619eeda891e8cc1c63da8569a2acced7cec05584a9eb939244c3', 'openubmc-target-runtime/openubmc_target_runtime/credential_file.py': '466faa0de59427fd21bf3e2a02a3cf3c48198de987083def36fdd893acb15c62', 'openubmc-target-runtime/openubmc_target_runtime/credentials.py': '14ebf93ad37a3824f0c1117b3e0599aac10cf7b15e192fe3671da172ed5f6453', 'openubmc-target-runtime/openubmc_target_runtime/delivery.py': '80b9d097c993683028004a03e450c737dff8772c0252fd13d49f58e958c55dcb', 'openubmc-target-runtime/openubmc_target_runtime/diagnosis_record.py': 'd3741ce0546a97e3c55959e869b0cfd93979b58e21e51c722525b993a51a7f29', 'openubmc-target-runtime/openubmc_target_runtime/diagnostic_receipt.py': '3247e52130caed3e7a83c528da1bb3e035f059d0d58244b8ae626fb396bfba24', 'openubmc-target-runtime/openubmc_target_runtime/diagnostic_request.py': 'd8b529a0a01dce8cb480e2c3c46abf4ce790c29422dd78eadac7811e55a811b4', 'openubmc-target-runtime/openubmc_target_runtime/distribution.py': '6837a58ef13b91f841e0ab416ced1d700b4eebe8067ac342aeb8c1c88d14b8ce', 'openubmc-target-runtime/openubmc_target_runtime/domain_packs.py': '969e74eb37694ac776e172a4961ea58dfbee7b70bdcfe1fb812510c79d61c1dc', 'openubmc-target-runtime/openubmc_target_runtime/domain_runtime.py': '10488274d8fb8d8cd1830c78706d8fbf45f4faa332ee9c91ff1baaf7c462c53f', 'openubmc-target-runtime/openubmc_target_runtime/effect_activity.py': '5962c133ce24ea91133f2a9407b43e1189c140052f1946d35318f5233bf87789', 'openubmc-target-runtime/openubmc_target_runtime/effect_runner.py': '37ffaa0de80503836ac6ed14dc0961738dfed5826e12e607a33e5298c3edc88b', 'openubmc-target-runtime/openubmc_target_runtime/evidence_store.py': '7704d29c25f13680bb204ba747ca36f4f535e0b92da1e37b6cbb1b7a1324c3c1', 'openubmc-target-runtime/openubmc_target_runtime/incident.py': '94d8d21dde176995a29ff788d4bdeb2d5eeeb25a363e6a9ed8743aba8f6b3358', 'openubmc-target-runtime/openubmc_target_runtime/lifecycle.py': '34ce024457dd2f5acfa4dcca4ac05ab3f68fcb12371d632085d2307ab3e8a192', 'openubmc-target-runtime/openubmc_target_runtime/mcp.py': 'e69c9c5e1b858766e9c9c05c4f77ce8889866a090f7d1152e46a989f178151b5', 'openubmc-target-runtime/openubmc_target_runtime/mcp_lifecycle.py': 'a9e1903331c6b8f50650d29de55f60fc4a214241bfbafce379a4516efe8bd0d8', 'openubmc-target-runtime/openubmc_target_runtime/mdb_query.py': '0faa17f690b13b2f6f6e47fb7d8cd88afc53547ca44ccae1ab930dad77c342f2', 'openubmc-target-runtime/openubmc_target_runtime/model_planning.py': '32d2486e88303b141aa533cb63b0acd7dbe9732948743dc93218bfc4d599f20e', 'openubmc-target-runtime/openubmc_target_runtime/mutation.py': 'eaadfaed0b32b3eacb21ea0c4132e4784830f6ab6dcf28b0b148b8a66b003d8d', 'openubmc-target-runtime/openubmc_target_runtime/observation.py': 'd7218265e99d5602b3459cf9a4b0f669b6131d9c3160ed82ab7e2ee28e617258', 'openubmc-target-runtime/openubmc_target_runtime/openssh.py': '42fdacee92cc75b2e174afedf536a64bdc6fe5ea652abeced6d19000cd8002a1', 'openubmc-target-runtime/openubmc_target_runtime/operation_contracts.py': '8e9004664b173e3d90045f2ce29cba39a5c451871bc960bccd01ee18efa53905', 'openubmc-target-runtime/openubmc_target_runtime/orchestration.py': 'de00d65e43f66fd3df5e4650f8fb1db40126e12ef604f2381bcc8237cf7f5e23', 'openubmc-target-runtime/openubmc_target_runtime/redaction.py': '82887026658ca2284de61f95f4a4afd8031a8e7d0a78d22ecd9b9252c8a126da', 'openubmc-target-runtime/openubmc_target_runtime/release.py': '2bed97148d4b99640b1314b00a2828a765f450e1989f5d6e5885a03c2978d2e3', 'openubmc-target-runtime/openubmc_target_runtime/replay.py': '008b3269fcae96454e6675977f204c183ae987138f248eaa31d70b55142fb42b', 'openubmc-target-runtime/openubmc_target_runtime/run_engine.py': '3e2ad1a8b0cf147087e3bf0137a9261060ced4e99e760f24d6048585e27aa9a5', 'openubmc-target-runtime/openubmc_target_runtime/run_store.py': 'b4424b8b5a1dc7a107f743a4853c717b4d09c598eea253f07bf5ace1074f0b87', 'openubmc-target-runtime/openubmc_target_runtime/runtime.py': '9ec951b594956a7bfd95820383e20e553a207298f34012a1c1e4f691c5c2db79', 'openubmc-target-runtime/openubmc_target_runtime/runtime_adapter.py': '9a0e506ddef921d3c6a61013de99e28e56e6ae3c77a82c2b2aa7a0277adf6ab4', 'openubmc-target-runtime/openubmc_target_runtime/scheduler.py': '3ac272419e6eb75f5ba21a7eb832a4daceb9d66fba0428f697fadc7b240fe65e', 'openubmc-target-runtime/openubmc_target_runtime/semantic_runtime.py': '5e4713bdf5d0e54882d7d1ee0f39dca5662df28bd430dff042751f386ef7872f', 'openubmc-target-runtime/openubmc_target_runtime/session_outcome.py': 'd17b8922cf731e3409f552751984d09c18a53bcfbb2191f7b0a119c62648559a', 'openubmc-target-runtime/openubmc_target_runtime/systemd_contract.py': '26e9ad19882ef0e7b7aaa769f9260d9b755cd285bc1fc458f28c500d11dd8e44', 'openubmc-target-runtime/openubmc_target_runtime/task_context.py': '002b179593dd14b815916f9a1db3a10bb0c72f44cd4bd069b3429c76b271280c', 'openubmc-target-runtime/openubmc_target_runtime/telnet.py': '352ee0b2ce0007d3f670142a245506a1d7bb58f802ca7840d224384ebc695791', 'openubmc-target-runtime/openubmc_target_runtime/validation_readiness.py': 'a279e4d174e6a79ed614f346b5479490f0a9adf211cf7f442f8873ab3ca274fd', 'openubmc-target-runtime/openubmc_target_runtime/workflow.py': '53641d025ad25351aac9bcef62e69fb5307c7b6a0b9f77d0ac088a8958b168f3', 'openubmc-target-runtime/tools/benchmark_context_runtime.py': '89a801ecaa64498e2d73b8db340bd93756b3b5ad416db02b5475be1f8b9f00d3', 'openubmc-target-runtime/tools/package_runtime_skill.py': '4dce043d7654aa5a775f48c67df23559f13bb86a5f54dc2ee0c2351fb432ea95', 'openubmc-target-runtime/tools/runtime_loader.py': '2589151e12d610f7389136a8b0cefa87319b24dc13d0d35f948247f419145c3f', 'openubmc-target-runtime/tools/smoke_debug_context.py': '7e430c81350560ccccefc680e21529cd27dedd894dfca90ac1da6acbc433a504', 'openubmc-upgrade/SKILL.md': 'd77d570ede1d583b95c75e379d90b226d21d7071ec1ca929d2a1e757be782c24', 'openubmc-upgrade/agents/openai.yaml': '53cb74381a5d432b62ad00678a867b08763bc3056a0122a8a8c1909c046083cd', 'openubmc-upgrade/openubmc_upgrade/__init__.py': 'd1205b7fbb71e1da441fb53d6aeaf9a6ee260bc4decde837dbd48488b231d474', 'openubmc-upgrade/openubmc_upgrade/operation_state.py': 'ee7749862f212dc8816bd3a404e957c551787e7882662945f7047b18469de971', 'openubmc-upgrade/openubmc_upgrade/runtime_backend.py': '89170bd84b4bb9633da9dd0b28a4af2b542164ccf269839ace4a277068652bac', 'openubmc-upgrade/openubmc_upgrade/task_diagnostics.py': '124e4606538de3edd5f376c63d401b81bb6e4d8b0eee95c18721b3c5448257d9', 'openubmc-upgrade/openubmc_upgrade/webui.py': 'b15602181689f9882d13ded099659347cffd4399852f691eca45916ba62a0756', 'openubmc-upgrade/references/redfish-upgrade.md': 'd8b914c3167d1bfe6dab812efd9a3490a3ecbfc5e665f651b2f7e6adefbfe402', 'openubmc-upgrade/references/webui-upgrade.md': '46c78f0cf4e26341ce89022dd25dfcb462bccd762d1d09ddce6cdf041978a951', 'openubmc-upgrade/scripts/artifact_identity.py': '4c0a4c9b9e7c2c1c1aab74464ba1f6c5236547435cdb802a5cf0a5383d31cefd', 'openubmc-upgrade/scripts/preflight_upgrade.py': 'b71e5c1fb70a9562a80e9e83c5792e6cbb64f920fccdfeddfbfc0f3a9535a004', 'openubmc-upgrade/scripts/redfish_credentials.py': 'c674b9458d7b09bc033942b58595f88992ae6370d76fab0bb24899ff6ca61f5b', 'openubmc-upgrade/scripts/target_runtime_adapter.py': 'aa0ab23039db30a571cd15fa239e09b3815ff0f81d2f6c0c11e6f7f3a7f85c61', 'openubmc-upgrade/skill.json': 'b329c01dcac3e60df5996f0de2ebdb8651535ea66c73d493dbe623d0e1c5ecc2', 'qemu-testing/SKILL.md': 'd575f68ba49337b8585ebf66a95bc005231e6040b562d25dc01ceb4404ee9d16', 'qemu-testing/agents/openai.yaml': '2347231164076a1bc183947a74f92edf0771d2b27251066767208eccfe5a0209', 'qemu-testing/references/qemu-verification.md': '22b5b1bec6db19f901e423f02d04b08ed055edf32cc37e9dff5d4346f482272e', 'qemu-testing/skill.json': '412db8eabe71aac71c92f8c64c5504be1118cfb724ebca3be328033803a859d4', 'testing/SKILL.md': '93662632203524968af5c0868e4fefe8dbcf0b3d9cf0747b9f38f41a8eac00e9', 'testing/agents/openai.yaml': '43897decfaec6d3d59f14e9d6da917eae35e3d23d48174c70ed57969c5782439', 'testing/evals/evals.json': '4acbbf08e1057639c1fae8061e30da258a17ea9d7f036f6e4a0deaba89087690', 'testing/skill.json': '00f42eb9a7d2dbbcaedd9ecfbc97a99cadbf7cdbe366a8df03200d8879420d4a'}
COMPOSITION_ROOTS = ('openubmc-target-runtime', 'openubmc-environment-setup', 'openubmc-debug', 'openubmc-log-analyzer', 'openubmc-developer', 'openubmc-build', 'openubmc-upgrade', 'openubmc-live-patch', 'testing', 'openubmc-publish', 'lua-component', 'qemu-testing')
SOURCE_COMMIT = "382dc9b8caa24b23fe35d28a46d25372748ab624"
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

# Carry the already-verified inventory to Python children. Derive it from
# captured bytes, never from a fresh scan that could accept intervening drift.
snapshot_files = dict(COMPOSITION_FILES)
for relative, content in RUNTIME_CONTENT.items():
    snapshot_files["installed-runtime/openubmc_target_runtime/" + relative] = hashlib.sha256(content).hexdigest()
snapshot_files[entrypoint_relative.as_posix()] = hashlib.sha256(ENTRYPOINT_CONTENT).hexdigest()
receipt = {"schema": "openubmc.runtime-snapshot.v1", "root": str(snapshot_root.resolve()),
           "source_commit": SOURCE_COMMIT, "runtime_content_digest": EXPECTED_DIGEST,
           "mcp_entrypoint_digest": actual_entrypoint_digest, "files": snapshot_files}
receipt_path = snapshot_root / ".openubmc-runtime-snapshot.pending"
receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
receipt_path.chmod(0o400)
receipt_path.replace(snapshot_root / ".openubmc-runtime-snapshot.json")
PACKAGE_ROOT = snapshot_package
MCP_ENTRYPOINT = snapshot_entrypoint

# Never import stale sourceless bytecode from a release source tree.
sys.dont_write_bytecode = True
_fresh_pycache_root = tempfile.TemporaryDirectory(prefix="openubmc-runtime-pycache-")
sys.pycache_prefix = _fresh_pycache_root.name

os.environ["OPENUBMC_MCP_SOURCE_COMMIT"] = SOURCE_COMMIT

sys.path.insert(0, str(PACKAGE_ROOT.parent))
sys.path.insert(0, str(MCP_ENTRYPOINT.parent))
runpy.run_path(str(MCP_ENTRYPOINT), run_name="__main__")
