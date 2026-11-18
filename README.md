# CS711-CS801-to-XCTB
Convert Connect Systems CS711 and CS801 to mainstream DMR radio XCTB

## Trademarks & Disclaimer

MOTOROLA, MOTO, MOTOROLA SOLUTIONS, and MOTOTRBO are trademarks or registered trademarks of Motorola Trademark Holdings, LLC. All other trademarks are the property of their respective owners.

This project is an independent work and is not affiliated with, endorsed by, or sponsored by Motorola Solutions, Inc.

This is an **independent experimental migration utility**, not a Motorola or Connect Systems product. Consult your software licenses before using or distributing codeplugs; this repository ships no vendor binaries, original firmware, or real radio programming. Only work with codeplugs and radio equipment you are authorized to access and program. Never transmit on an unauthorized frequency.

# CS711 RDB → Motorola CPS2 XCTB converter (experimental)

A standalone Python 3 utility for migrating **Connect Systems CS711** programming from an `.rdb` file into a separately supplied **Motorola CPS2 `.xctb`** template. It also offers an RDB-only source inventory export.

**This repository contains source code only. It must not include real `.rdb`, `.xctb`, `.ctb`, passwords, serial numbers, private profiles, output reports, or decrypted radio configurations.** The utility is not affiliated with or endorsed by Connect Systems or Motorola Solutions.

> **TEST-ONLY.** The generated file has internal archive/XML, zone, frequency, and signaling reference checks, but has **not** been validated in the Motorola CPS GUI or on a radio. An internally consistent file is not proof it can be opened or programmed successfully. Verify RF settings, transmit permissions, signaling and channel behavior in CPS before any programming.

## Supported formats and limitations

- One observed **376,832-byte CS711 RDB layout** identified by `CS711` at byte offset 8192. The parser uses layout-specific fixed offsets. It is **not** a universal Connect Systems RDB decoder.
- Motorola CPS2 XCTB data model **`2.159`**, protection type `d`, using a user-supplied compatible R7 template. Other models/versions are rejected. You must already have the appropriate Motorola codeplug and software rights/access.
- Requires a target Motorola template that contains conventional analog/digital personalities, zones, QCII systems and contacts, and scan/roam template entries.
- Exports all populated source channels, zones, digital contacts, a decoded receive group, and populated CS711 two-tone definitions. Source scan/roam membership may require a private profile because source-specific routing rules must not be guessed.
- Creates **new uniquely identified personalities per imported zone occurrence**, preventing CPS from fabricating default-named duplicate channels.
- Imports conventional analog RX/TX tones, digital talkgroup/slot/color-code, RX group members, source zone order, and non-zoned channels (placed into holding zones).
- Applies admit criteria **only to imported channels**: RX-only = Channel Free; TX-enabled = Always; digital In Call Criteria = Always; digital RX-only GNSS/Data Revert = None.
- Imports QCII Decode Defs dynamically: source `Two Tone` → Motorola `A-B` (source tones A and B); source `Long Tone` → Motorola `A-B/Long C` (A=296.5 Hz and B=1930.2 Hz **documented placeholder tones**, C=source long tone). The inactive second long-tone frequency is ignored. Unsupported tone codes or source types abort rather than silently substituting values.
- Maps the source **radio alias** to Motorola Radio Alias and Caller Alias if supported by the template; source power-on message is **not mapped**.
- Leaves unknown two-tone service/alert/recording flags unmapped and records raw values for review. Existing Motorola channel personalities are checked for preservation. **A profile can deliberately change existing scan-list membership, roaming lists, and selected existing QCII formats**—review before use.

## Requirements

- Python 3.9 or newer.
- `cryptography` (see `requirements.txt`).
- The user's **own** source CS711 `.rdb` file and **own** original R7 `.xctb` target codeplug. **No XLSX export is required.**

On Windows:

```powershell
py -3 -m pip install -r requirements.txt
py -3 cs711_to_xctb.py --help
```

On Linux/macOS:

```bash
python3 -m pip install -r requirements.txt
python3 cs711_to_xctb.py --help
```

## 1. Inspect your source RDB first

This mode needs **no Motorola template**. It exports a PRIVATE JSON inventory of channels, names, frequencies, contacts, zones, scanned list indices, roaming talkgroups, and two-tone definitions:

```powershell
py -3 cs711_to_xctb.py "my-source.rdb" --inspect-source -o "private-source-inventory.json"
```

**Do not post the generated inventory**. It contains your actual system information. It can help you construct a private migration profile.

## 2. Configure scan/roam migration safely

Most real RDBs have scan and/or roaming assignments. A complete mapping is necessary to preserve those associations. The script therefore **refuses to build** if your source refers to a scan or roam list for which no mapping was supplied. It does **not** invent list memberships.

Copy `profile.example.json` outside your public repository, rename it to `my-private-profile.json`, and fill in your specific source list memberships and mapping keys. Leave the private file out of version control. Profile keys:

| Profile key | Meaning |
|---|---|
| `scan_lists` | Target scan-list names and explicitly ordered channel members (the first member must be `Selected`) |
| `source_scan_list_index_map` | Maps CS711 channel `list_index` numbers to the scan-list names you created |
| `roam_lists` | Explicitly ordered roaming members; `required_talkgroup_id` enforces single-talkgroup lists |
| `roam_list_by_talkgroup` | Maps auto-roaming channels' TX talkgroup IDs to roaming-list names |
| `remap_existing_roam_lists` | Optional: replace memberships of explicitly named target lists while reusing their UUIDs |
| `frequency_corrections` | Optional, individually numbered TX-frequency fixes; **never inferred** |
| `existing_qcii_ab_systems` | Optional target QCII systems to change from an existing format to `A-B` |
| `channel_rules` | Optional confirmed per-channel scan/roam overrides |
| `exclude_exact_channel_names` | Optional list-member exclusions; **not** deletions of channels |
| `must_keep_channel_names` | Optional validation that expected channels remain present |
| `zone_regressions` | Optional test cases for zone position/channel identity |
| `expected_*` | Optional source/target count assertions for a known installation |

Channel names, talkgroup IDs, custom zone fixes, and any original target system names belong in the **private JSON**, not in the Python source.

## 3. Convert

```powershell
py -3 cs711_to_xctb.py "my-source.rdb" "my-original-R7.xctb" `
  --profile "my-private-profile.json" `
  -o "my-radio-TEST-ONLY.xctb"
```

When the source has no scan/roam associations and no one-off corrections are necessary, you may omit `--profile`. Existing files are **not** overwritten unless `--force` is specified; the script refuses to overwrite either input file. Keep a separate backup of your radio codeplugs.

Each successful build generates:

- `my-radio-TEST-ONLY.xctb`
- `my-radio-TEST-ONLY.qa.json`
- `my-radio-TEST-ONLY.channels.csv`
- `my-radio-TEST-ONLY.zones-verified.csv`
- `my-radio-TEST-ONLY.2tone-verified.csv`
- `my-radio-TEST-ONLY.2tone-source-audit.json`

**These outputs are private radio configuration data too.** Do not commit them to a public GitHub repository.

## Run the source-only automated tests

```powershell
py -3 -m unittest discover -s tests -v
```

The repository tests use a **synthetic, fabricated CS711 RDB fixture** and do not contain any actual user codeplug data. Real-world R7 conversion also needs your own compatible template and should be checked in CPS.

## Publishing checklist

1. Publish `cs711_to_xctb.py`, `README.md`, `requirements.txt`, `profile.example.json`, `tests/`, `.gitignore`, and `LICENSE` only.
2. **Do not publish** real RDB/XCTB files, private JSON profiles, decrypted XML, actual inventory/QA reports, local backups, or archives containing those files.
3. Verify `git status` and inspect every staged file using `git diff --cached --stat` before pushing.
4. Review the disclaimer and compatibility limitations with anyone using the program.

## Security/ownership note

This is an **independent experimental migration utility**, not a Motorola or Connect Systems product. Consult your software licenses before using or distributing codeplugs; this repository ships no vendor binaries, original firmware, or real radio programming. Only work with codeplugs and radio equipment you are authorized to access and program. Never transmit on an unauthorized frequency.
