# ATT&CK for ICS mapping

Every rule alert carries the MITRE ATT&CK for ICS techniques its rule maps
to, in `techniques` (`[{"id": "T0855", "name": "Unauthorized Command
Message"}]`). They show in the **Rule alerts** table, linking to the MITRE
pages, and in every notification sink: a fact in Slack and Teams, the
`techniques` array in the webhook JSON, and `techniques=T0843,T0889` in
syslog.

The mapping lives in `internal/alerts/attack.go`. A test fails if a
built-in rule has no entry, so a new rule cannot ship without someone
choosing its techniques; "none" is an explicit choice for rules where no
single technique fits (a raw volume count, a weakness rather than an attack
step). Rules defined by the operator (custom thresholds, `watchlist:*`,
`policy:*` and `filter:*` hits) have none.

| Rule | Techniques |
|------|------------|
| `dns_query_volume` | none |
| `tcp_connection_volume` | none |
| `target_spread` | [T0846](https://attack.mitre.org/techniques/T0846/) Remote System Discovery |
| `rogue_dhcp_server` | [T0830](https://attack.mitre.org/techniques/T0830/) Adversary-in-the-Middle |
| `rogue_ipv6_ra_source` | [T0830](https://attack.mitre.org/techniques/T0830/) Adversary-in-the-Middle |
| `gateway_mac_changed` | [T0830](https://attack.mitre.org/techniques/T0830/) Adversary-in-the-Middle |
| `baseline_new_flow` | [T0886](https://attack.mitre.org/techniques/T0886/) Remote Services |
| `zone_no_conduit` | [T0886](https://attack.mitre.org/techniques/T0886/) Remote Services |
| `zone_level_skip` | [T0886](https://attack.mitre.org/techniques/T0886/) Remote Services |
| `modbus_write` | [T0855](https://attack.mitre.org/techniques/T0855/) Unauthorized Command Message<br>[T0836](https://attack.mitre.org/techniques/T0836/) Modify Parameter |
| `modbus_diagnostic` | [T0816](https://attack.mitre.org/techniques/T0816/) Device Restart/Shutdown |
| `s7_write` | [T0855](https://attack.mitre.org/techniques/T0855/) Unauthorized Command Message<br>[T0836](https://attack.mitre.org/techniques/T0836/) Modify Parameter |
| `s7_control` | [T0858](https://attack.mitre.org/techniques/T0858/) Change Operating Mode |
| `s7_program` | [T0843](https://attack.mitre.org/techniques/T0843/) Program Download<br>[T0889](https://attack.mitre.org/techniques/T0889/) Modify Program |
| `dnp3_control` | [T0855](https://attack.mitre.org/techniques/T0855/) Unauthorized Command Message |
| `dnp3_diagnostic` | [T0816](https://attack.mitre.org/techniques/T0816/) Device Restart/Shutdown<br>[T0804](https://attack.mitre.org/techniques/T0804/) Block Reporting Message |
| `enip_write` | [T0855](https://attack.mitre.org/techniques/T0855/) Unauthorized Command Message<br>[T0836](https://attack.mitre.org/techniques/T0836/) Modify Parameter |
| `enip_control` | [T0816](https://attack.mitre.org/techniques/T0816/) Device Restart/Shutdown |
| `bacnet_write` | [T0855](https://attack.mitre.org/techniques/T0855/) Unauthorized Command Message<br>[T0836](https://attack.mitre.org/techniques/T0836/) Modify Parameter |
| `bacnet_control` | [T0816](https://attack.mitre.org/techniques/T0816/) Device Restart/Shutdown<br>[T0804](https://attack.mitre.org/techniques/T0804/) Block Reporting Message |
| `iec104_control` | [T0855](https://attack.mitre.org/techniques/T0855/) Unauthorized Command Message |
| `iec104_diagnostic` | [T0816](https://attack.mitre.org/techniques/T0816/) Device Restart/Shutdown |
| `opcua_write` | [T0855](https://attack.mitre.org/techniques/T0855/) Unauthorized Command Message<br>[T0836](https://attack.mitre.org/techniques/T0836/) Modify Parameter |
| `opcua_insecure` | [T0830](https://attack.mitre.org/techniques/T0830/) Adversary-in-the-Middle |
| `mqtt_anonymous` | none |
| `asset_changed` | [T0839](https://attack.mitre.org/techniques/T0839/) Module Firmware |
