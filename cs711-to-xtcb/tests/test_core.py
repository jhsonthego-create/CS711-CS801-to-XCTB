"""Public synthetic unit tests. Contains NO real radio programming."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'cs711_to_r7_xctb.py'
spec = importlib.util.spec_from_file_location('cs711_to_r7_xctb', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def put_u16_text(data, offset, text, max_bytes=32):
    enc = text.encode('utf-16le')
    assert len(enc) <= max_bytes
    data[offset:offset+max_bytes] = enc.ljust(max_bytes, b'\0')


def synthetic_rdb():
    data = bytearray(376832)
    data[8192:8197] = b'CS711'
    put_u16_text(data, 14464, 'Group Example')
    struct.pack_into('<I', data, 14464+32, 123456)
    put_u16_text(data, 88192, 'Example Analog')
    struct.pack_into('<II', data, 120192, 146520000, 146520000)
    data[120192+8] = 0x17  # analog channel
    data[120192+16:120192+20] = b'\xff\xff\xff\xff'  # CSQ
    put_u16_text(data, 152192, 'Sample Zone')
    data[152192+36] = 1
    struct.pack_into('<H', data, 152192+48, 1)
    struct.pack_into('<I', data, 58784, 1)
    put_u16_text(data, 58784+4, 'Example RX')
    struct.pack_into('<H', data, 58784+36, 1)
    put_u16_text(data, 8704, 'EXAMPLE')
    put_u16_text(data, 8744, 'HELLO')
    struct.pack_into('<HHHH', data, 255264, 5539, 6883, 0x0126, 0x0300)
    struct.pack_into('<HHHH', data, 255272, 7674, 9032, 0x0122, 0x0300)
    return bytes(data)


class CS711CoreTests(unittest.TestCase):
    def test_source_two_tone_parsing_and_long_tone_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'synthetic.rdb'
            p.write_bytes(synthetic_rdb())
            channels, contacts, zones, rx, two = module.read_live_rdb(p)
            self.assertEqual(len(channels), 1)
            self.assertEqual(channels[0]['channel_alias'], 'Example Analog')
            self.assertEqual(zones[0]['ids'], [1])
            self.assertEqual(two['radio_alias'], 'EXAMPLE')
            self.assertEqual(two['power_on_message_unmapped'], 'HELLO')
            one, sixteen = two['decode_definitions']
            self.assertEqual((one['format'], one['tone_a_hz'], one['tone_b_hz']), ('A-B', 553.9, 688.3))
            self.assertEqual((sixteen['format'], sixteen['tone_a_hz'], sixteen['tone_b_hz'], sixteen['tone_c_hz']), ('A-B/Long C', 296.5, 1930.2, 767.4))
            self.assertEqual(sixteen['source_tone_2_hz'], 903.2)

    def test_inventory_contains_discovered_indices(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'synthetic.rdb'
            j = Path(tmp)/'private-inventory.json'
            p.write_bytes(synthetic_rdb())
            module.inspect_source(p, j)
            d = json.loads(j.read_text())
            self.assertEqual(d['two_tone']['decode_definition_count'], 2)
            self.assertEqual(d['channels'][0]['channel_alias'], 'Example Analog')
            with self.assertRaises(ValueError):
                module.inspect_source(p, j)  # no implicit overwrites

    def test_profile_rejects_unsupported_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'profile.json'
            p.write_text('{"an_unsupported_option": true}')
            with self.assertRaises(ValueError):
                module.load_profile(p)

    def test_frequency_code_map(self):
        self.assertEqual(module.QCII_TONE_CODES[553.9], 'STR_150')
        self.assertEqual(module.QCII_TONE_CODES[688.3], 'STR_154')
        self.assertEqual(module.QCII_TONE_CODES[767.4], 'STR_156')


if __name__ == '__main__':
    unittest.main()
