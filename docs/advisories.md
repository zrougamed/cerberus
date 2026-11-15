# Advisory matching

Cerberus can tell you which of your controllers have published security
advisories, without internet access: it matches the asset inventory
(vendor, model, firmware the devices report about themselves) against an
offline bundle built from public advisories.

## Getting a bundle

Each release attaches `advisories.json`, built from CISA's CSAF feed of
ICS advisories (`csaf_files/OT/white` in github.com/cisagov/CSAF). Copy it
next to Cerberus and either put it at `<data dir>/advisories.json`, where
it is found automatically, or set `CERBERUS_ADVISORIES_FILE` to its path.

To build a fresh one (on any machine with internet access, then carry the
file over):

```sh
git clone --depth 1 --filter=blob:none --sparse https://github.com/cisagov/CSAF
git -C CSAF sparse-checkout set csaf_files/OT/white
go run ./tools/advisorygen -in CSAF/csaf_files/OT/white -out advisories.json
```

Any directory of CSAF 2.0 security advisories works, for example a
vendor's own feed; `-source` names it in the bundle. The full CISA feed
gives about 4,000 advisories in a 3.7 MB file that loads in under 100 ms
and uses about 11 MB of memory.

To swap bundles without a restart, replace the file and use
`POST /api/v1/advisories/reload` (API token). The Assets page shows the
bundle's date and warns once it is more than 90 days old.

## How matching works

| Asset field | Advisory field | Rule |
|-------------|----------------|------|
| Reported vendor (else the OUI vendor) | vendor | Same company, ignoring suffixes such as AG, Inc., GmbH |
| Reported model | product name | One contains the other, compared on letters and digits only: `S7-1500` matches `SIMATIC S7-1500 CPU` |
| Reported firmware | affected versions | Numeric parts compared: `V32.011` = 32.11, `6.3_HF3` = 6.3.3 |

Version expressions understood: a bare version (exact), `<`, `<=`, `>`,
`>=`, `!=`, and VERS (`vers:generic/>=2.0|<3.1`, `vers:all/*`). Products
listed as fixed are not in the bundle.

Each match has a confidence:

- **affected version**: the firmware is in the affected range, or every
  version is affected;
- **product only**: the firmware is unknown or the advisory's range cannot
  be compared. Check the version on the device.

A device whose firmware is known and outside every affected range is not
listed.

## Limits

- Matching is only as good as what devices report. Some report a part
  number that advisories never mention (a Rockwell controller reports
  `1756-L83E`, advisories say `ControlLogix 5580`); those get no match.
  Family-level names (`S7-1500`) match every advisory for the family.
- Only devices with a reported identity (Modbus device identification, CIP
  ListIdentity, BACnet I-Am, PROFINET DCP) are matched.
- The bundle is a snapshot; it says nothing about advisories published
  after it was built.
