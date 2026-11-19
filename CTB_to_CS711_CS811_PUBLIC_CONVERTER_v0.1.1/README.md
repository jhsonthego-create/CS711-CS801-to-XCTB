# SAFETY UPDATE v0.1.1 — DONOR TWO-TONE CONTAMINATION

**Default conversion now refuses to generate an RDB.** The previous v0.1.0 retained the destination donor’s two-tone definitions even when absent from the Motorola CTB source. The two-tone binary tables have not been mapped well enough to clear safely. **Do not distribute v0.1.0 or its generated RDBs as source-faithful conversions.**

To enable an explicitly donor-preserving **private test only**, append `--allow-donor-two-tone`. This is not a safe public conversion: it retains donor two-tone programming. The correct public solution requires mapping and clearing the complete two-tone tables and channel references, followed by CPS testing.

# CTB v1 → CS711 / CS811 (experimental)

Python scripts to convert genuine Motorola CPS1 `.ctb` files (MATRIX and GEMSTONE archives) into Connect Systems `.rdb` programming files, **using a genuine CPS-created donor for the exact destination model**.

*Does not contain any codeplug, Motorola key, AES password, user data, or donor RDB.* Requires Python 3.9+ with `pip install cryptography lxml`.

Run from the folder containing all three `.py` files:

```
python ctb_to_cs_rdb.py input.ctb --config codeplug.cfg --model CS711 --donor donor-CS711.rdb --output output-CS711.rdb
python ctb_to_cs_rdb.py input.ctb --config codeplug.cfg --model CS811 --donor donor-CS811.rdb --output output-CS811.rdb
python verify_ctb_to_cs.py input.ctb --config codeplug.cfg --model CS711 --rdb output-CS711.rdb
```

The local `codeplug.cfg` needs the `[codeplug] key` and `iv` provided by the user's own CPS installation. The source CTB RSA signature is verified. Known 16-bit scan, contact, channel, roaming, and zone records are rebuilt in the donor binary. Private Motorola settings are not blindly copied across incompatible schemas.

Only one populated DMR RX group is supported in the observed RDB layout. Unsupported Motorola DMR contact types, invalid references, out-of-band channels, or over-capacity lists cause an explicit exception rather than a silent lossy conversion. Quick Call II and Motorola enhanced encryption are not migrated; donor settings outside known tables remain and should be inspected.

**Outputs require Connect Systems CPS open/save/reopen validation; they are not approved for immediate radio programming.** This project is experimental and unaffiliated with Motorola or Connect Systems.
