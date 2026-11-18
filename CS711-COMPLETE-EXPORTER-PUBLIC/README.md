# CS711 Complete Source Exporter (public)

Export supported Connect Systems CS711 `.rdb` codeplugs to decoded CSV, XML, text, full hex dump, and a lossless original-byte Base64 payload in XML. This is an **analysis export**, not a vendor CPS-importable XML. Unknown fields are preserved as raw bytes rather than invented as decoded settings.

Requires Python 3.9+ and the two included `.py` files in the same folder. The bundled decoder is shared with the public Motorola converter and may require `cryptography` for its import. Install with `python -m pip install cryptography`.

```shell
python export_cs711.py YOUR_CODEPLUG.rdb
python export_cs711.py YOUR_CODEPLUG.rdb -o my_export --include-original
```

**Privacy:** The script and public ZIP contain no actual radio data. Generated exports **contain your codeplug's programming and radio alias**, including the complete original RDB embedded in XML. Do not publish an export unless you intend to disclose that information.

Supported: the tested CS711 RDB binary layout (376,832 bytes, CS711 marker at byte 8192). Other firmware/layouts are rejected, not silently misparsed.
