# Component Ownership Hints

Use these names only as search hints after resolving the actual repository or workspace. Verify ownership from manifests, service/MDS definitions, code callers, and repository rules; do not infer a path from this list.

- `account`: accounts, authentication, roles, and access policy.
- `chassis`: chassis state, intrusion, UID, and LEDs.
- `fructrl`: power control, reset, power locks, and power policy.
- `frudata`: FRU/EEPROM parsing and access.
- `general_hardware`: board-level hardware services and firmware update support.
- `hica`: subsystem/systemd/Skynet startup orchestration.
- `mdb_interface`: shared MDB/D-Bus interface and path source models.
- `network_adapter`: NIC/port/optics and NCSI/MCTP/LLDP behavior.
- `observability`: logging, metrics, and tracing.
- `pcie_device`: PCIe topology, devices, links, and cables.
- `power_mgmt`: PSU/power health, modes, and power firmware behavior.
- `rackmount`: northbound Redfish/CLI/SNMP/web mapping.
- `sensor`: sensors, thresholds, health, and event reporting.
- `storage`: controllers, disks, RAID, logical drives, and health.
- `thermal_mgmt`: fans, cooling loops, pumps, valves, and thermal policy.
- `vpd`: CSR/PSR and vendor data.
- `webui`: browser UI behavior.

Toolchain and manifest repository names vary by distribution. Discover them from the current workspace instead of assuming a fixed layout.
