#!/usr/bin/env python3
"""CS711 RDB -> Motorola CPS2 XCTB migration (experimental; Python 3.9+).

This script does not bundle, download, or contain radio codeplugs. It operates
on codeplugs supplied locally by the user. The decoder supports ONE observed
376,832-byte CS711 RDB layout and Motorola CPS2 XCTB model 2.159.

For migration-specific zone, scan, roam and frequency decisions, pass an
explicit JSON profile with --profile. The generator will refuse to silently
lose configured source scan/roam assignments when no mapping is supplied.

Usage:
  python cs711_to_xctb.py SOURCE.rdb ORIGINAL.xctb -o TEST.xctb
  python cs711_to_xctb.py SOURCE.rdb ORIGINAL.xctb \
    --profile private-profile.json -o TEST.xctb

Unverified in Motorola CPS GUI and untested on radio; test and confirm all RF
settings, scan/roam behavior, signaling, and legal TX permissions before use.
"""

import argparse, base64, copy, csv, gzip, hashlib, json, re, secrets, struct, uuid, zlib
from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__version__ = '0.1.0'

DEFAULT_PROFILE = {
    'exclude_exact_channel_names': [],
    'scan_lists': [], 'roam_lists': [], 'channel_rules': [],
    'frequency_corrections': {},
    'remap_existing_roam_lists': {},
    'roam_list_by_talkgroup': {},
    'source_scan_list_index_map': {},
    'existing_qcii_ab_systems': [],
    'must_keep_channel_names': [], 'zone_regressions': [],
}

def load_profile(path):
    """Load optional private per-codeplug rules; never embed them in Python."""
    if path is None:
        return copy.deepcopy(DEFAULT_PROFILE)
    supplied = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(supplied, dict):
        raise ValueError('Profile must be a JSON object')
    unknown = set(supplied) - (set(DEFAULT_PROFILE) | {
        'expected_source_channels', 'expected_original_personalities',
        'expected_imported_zone_positions', 'expected_two_tone_count',
    })
    if unknown:
        raise ValueError('Unknown profile settings: ' + repr(sorted(unknown)))
    result = copy.deepcopy(DEFAULT_PROFILE)
    result.update(supplied)
    for key in ('scan_lists', 'roam_lists', 'channel_rules',
                'exclude_exact_channel_names', 'existing_qcii_ab_systems',
                'must_keep_channel_names', 'zone_regressions'):
        if not isinstance(result[key], list):
            raise ValueError('Profile setting ' + key + ' must be an array')
    for key in ('frequency_corrections', 'remap_existing_roam_lists',
                'roam_list_by_talkgroup', 'source_scan_list_index_map'):
        if not isinstance(result[key], dict):
            raise ValueError('Profile setting ' + key + ' must be an object')
    return result


XSI = '{http://www.w3.org/2001/XMLSchema-instance}type'
ROOT_NS = 'http://schemas.datacontract.org/2004/07/Motorola.CommonCPS.Server.EntityModel'
DEFAULT_SEED = b'627842'

# Standard Motorola Quick-Call II frequency to code mapping. This is a CODEBOOK,
# not hardcoded source programming: the programmed frequencies must come from RDB.
# Source: Motorola RVN4002K service manual, Appendix 6, Quik-Call II Table 1.
# A few relevant values are also independently present in the R7 source template.
QCII_TONE_CODES = {
  288.5:'STR_138', 296.5:'STR_108', 349.0:'STR_111',
  368.5:'STR_112', 553.9:'STR_150', 584.8:'STR_151',
  617.4:'STR_152', 651.9:'STR_153', 688.3:'STR_154', 726.8:'STR_155',
  767.4:'STR_156', 810.2:'STR_157', 855.5:'STR_158',
  903.2:'STR_159', 928.1:'STR_129', 1930.2:'STR_200',
}
TPL_CODE = {
    '67.0': 'STR_XZ',
    '69.3': 'STR_WZ',
    '71.9': 'STR_XA',
    '74.4': 'STR_WA',
    '77.0': 'STR_XB',
    '79.7': 'STR_WB',
    '82.5': 'STR_YZ',
    '85.4': 'STR_YA',
    '88.5': 'STR_YB',
    '91.5': 'STR_ZZ',
    '94.8': 'STR_ZA',
    '97.4': 'STR_ZB',
    '100.0': 'STR_1Z',
    '103.5': 'STR_1A',
    '107.2': 'STR_1B',
    '110.9': 'STR_2Z',
    '114.8': 'STR_2A',
    '118.8': 'STR_2B',
    '123.0': 'STR_3Z',
    '127.3': 'STR_3A',
    '131.8': 'STR_3B',
    '136.5': 'STR_4Z',
    '141.3': 'STR_4A',
    '146.2': 'STR_4B',
    '151.4': 'STR_5Z',
    '156.7': 'STR_5A',
    '162.2': 'STR_5B',
    '167.9': 'STR_6Z',
    '173.8': 'STR_6A',
    '179.9': 'STR_6B',
    '186.2': 'STR_7Z',
    '192.8': 'STR_7A',
    '203.5': 'STR_M1',
    '206.5': 'STR_8Z',
    '210.7': 'STR_M2',
    '218.1': 'STR_M3',
    '225.7': 'STR_M4',
    '229.1': 'STR_9Z',
    '233.6': 'STR_M5',
    '241.8': 'STR_M6',
    '250.3': 'STR_M7',
}

def tpl_field_pair(node, direction, frequency, *, source_name):
    tone = format(float(frequency), ".1f")
    code = TPL_CODE.get(tone)
    if code is None or abs(float(tone) - float(frequency)) > 0.00001:
        raise ValueError(f"Unsupported Motorola TPL frequency {frequency!r} on {source_name} {direction.upper()}")
    set_field(node, "CP_RXTPLFREQ" if direction == "rx" else "CP_TXTTPLFREQ", tone)
    set_field(node, "CP_RXTPLCODE" if direction == "rx" else "CP_TXTPLCODE", code)

# Explicit documented placeholder A/B tones, used ONLY when converting a true
# CS711 single LONG tone to Motorola's A-B / Long C format.
LONG_C_DUMMY_A_HZ = 296.5
LONG_C_DUMMY_B_HZ = 1930.2
# Alias fields are identity/startup data, NOT two-tone decode definitions.
RADIO_ALIAS_OFFSET = 8704
POWER_ON_MESSAGE_OFFSET = 8744
TWO_TONE_DEFS_OFFSET = 255264
TWO_TONE_DEFS_CAPACITY = 16
TWO_TONE_DEF_SIZE = 8

def qcii_field_pair(node, tone, frequency, code, *, source_name):
    hz = round(float(frequency), 1)
    if abs(hz - float(frequency)) > .00001:
        raise ValueError('Unsupported fractional Quick-Call II tone for '+source_name)
    expected = QCII_TONE_CODES.get(hz)
    if expected is None:
        raise ValueError('QCII tone not in verified frequency/code map: '+str(hz)+' '+source_name)
    set_field(node, tone, format(hz,'.1f'))
    set_field(node, code, expected)

def apply_imported_admit_criteria(channel, source):
    """ONLY for cloned/imported CS711 personalities; never for existing R7 ones."""
    if source['rx_only']:
        set_field(channel,'CP_TXINHXPLEN','ONCHNNLFREE')
    else:
        set_field(channel,'CP_TXINHXPLEN','ALWAYS')
    if source['mode']=='Digital':
        set_field(channel,'CP_MYCALLADCRTR','ALWAYS')
        if source['rx_only']:
            set_field(channel,'CP_GPSRVRTPERSIT_Zone','NONE')
            set_field(channel,'CP_GPSRVRTPERSIT','NONE')
            set_field(channel,'CP_DATAREVCHANLISTIT','NONE')

ET.register_namespace('xsi','http://www.w3.org/2001/XMLSchema-instance')
ET.register_namespace('xsd','http://www.w3.org/2001/XMLSchema')


def sha(b):return hashlib.sha256(b).digest()
def xor(a,b):return bytes(x^y for x,y in zip(a,b))
def raw_decompress(data):return zlib.decompress(data,-15)
def raw_compress(data):
 c=zlib.compressobj(level=9,wbits=-15)
 return c.compress(data)+c.flush()
def guid():return str(uuid.uuid4())
def records(node):return [x for x in node if x.get(XSI)=='Record']
def fdict(node):return {x.get('Name'):x.get('Value') for x in node if x.get(XSI) in ('DBField','DBRefField')}
def field(node,name):
 x=next((x for x in node if x.get(XSI) in ('DBField','DBRefField') and x.get('Name')==name),None)
 if x is None:raise ValueError(f'Missing {name} in record {node.get("UUID")}')
 return x

def set_field(node,name,value,refer=None):
 x=field(node,name)
 x.set('Value',str(value))
 if x.get(XSI)=='DBRefField':
  x.set('ReferSetName',refer or '')
 elif refer:
  raise ValueError(f'Expected DBRefField for {name}')

def clone_record(x, number):
 out=copy.deepcopy(x)
 for e in out.iter('DBNode'):
  if e.get(XSI)=='Record':
   e.set('UUID',guid())
 out.set('Name',str(number))
 return out

def reindex(group):
 for idx,record in enumerate(records(group)): record.set('Name',str(idx))

def parse_archive(raw):
 start=raw.find(b'{\r\n  "version"')
 if start<4:raise ValueError('Not a recognized Motorola XCTB header')
 length=struct.unpack_from('<I',raw,start-4)[0]
 end=start+length
 if len(raw)<end or end-start<32:raise ValueError('Malformed archive header')
 header=json.loads(raw[start:end].decode('utf-8'))
 if header['type']!='xctb' or header['protect']!='d' or header['dataModelVersion']['Version']!='2.153.50':
  raise ValueError('Unsupported target data model / protection')
 iv=base64.b64decode(header['stamp'])
 if len(iv)!=16:raise ValueError('Invalid archive IV')
 seed=sha(DEFAULT_SEED)
 key=sha(xor(iv,xor(seed[:16],seed[16:])))
 ciphertext=raw[end:]
 decryptor=Cipher(algorithms.AES(key),modes.CBC(iv)).decryptor()
 padded=decryptor.update(ciphertext)+decryptor.finalize()
 pad=padded[-1]
 if pad not in range(1,17) or padded[-pad:]!=bytes([pad])*pad:raise ValueError('Invalid archive padding')
 compressed=padded[:-pad]
 plain=gzip.decompress(compressed)
 il=struct.unpack_from('<I',plain)[0]
 inner=json.loads(plain[4:4+il].decode('utf-8'))
 xml=plain[4+il:]
 if base64.b64encode(sha(xml)).decode()!=inner['checksum']:raise ValueError('Original archive XML SHA-256 mismatch')
 return raw[:start-4],header,inner,xml

def encode_archive(prefix, header, inner, xml):
 # Fresh cryptographic IV and derived key, no reuse of original IV.
 inner=inner.copy();inner['checksum']=base64.b64encode(sha(xml)).decode()
 payload=json.dumps(inner,ensure_ascii=False,indent=2).encode('utf-8')
 plain=struct.pack('<I',len(payload))+payload+xml
 zipped=gzip.compress(plain,compresslevel=9,mtime=0)
 iv=secrets.token_bytes(16)
 header=copy.deepcopy(header);header['stamp']=base64.b64encode(iv).decode()
 h=json.dumps(header,ensure_ascii=False,indent=2).replace('\n','\r\n').encode('utf-8')
 seed=sha(DEFAULT_SEED);key=sha(xor(iv,xor(seed[:16],seed[16:])))
 pad=16-(len(zipped)%16)
 encryptor=Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor()
 ciphertext=encryptor.update(zipped+bytes([pad])*pad)+encryptor.finalize()
 return prefix+struct.pack('<I',len(h))+h+ciphertext

def get_dbnode(xml):
 # Outer XML remains byte-identical except Base64 text; no loss of CPS attributes or namespaces.
 pattern=re.compile(rb'(<DBNodeCmpBytes>)([A-Za-z0-9+/=\s]+)(</DBNodeCmpBytes>)')
 m=pattern.search(xml)
 if not m:raise ValueError('Missing Motorola DBNodeCmpBytes')
 compressed=base64.b64decode(m.group(2),validate=True)
 raw=raw_decompress(compressed)
 root=ET.fromstring(raw)
 if root.tag!='DBNode':raise ValueError('Decompressed XML is not DBNode')
 return root,pattern

def u16txt(b):
 return b.decode('utf-16le','replace').split('\0',1)[0]

def unpack_tone(raw2):
 """CS711 analog tones: 0xffff CSQ; 0x8xxx DPL BCD; otherwise CTCSS BCD x10."""
 x=int.from_bytes(raw2,'little')
 if x==0xffff: return ('CSQ','')
 d=''.join(f'{z:x}' for z in [(x>>12)&7,(x>>8)&15,(x>>4)&15,x&15])
 if not d.isdigit():raise ValueError(f'Bad analog tone BCD: {x:04x}')
 if x&0x8000:return ('DPL',d[-3:])
 return ('TPL',str(int(d)/10))

def read_live_rdb(p):
 """Inspect the CS711 variant; the two workbook exports are NOT required."""
 raw=p.read_bytes()
 if len(raw)!=376832 or raw[8192:8197]!=b'CS711':raise ValueError('Unsupported CS711 RDB layout')
 contacts={}
 for idx in range(1,101):
  at=14464+(idx-1)*44
  name=u16txt(raw[at:at+32])
  if not name:break
  contacts[idx]={'name':name,'id':struct.unpack_from('<I',raw,at+32)[0]}
 channels=[]
 for idx in range(1,1001):
  at=120192+(idx-1)*32
  name=u16txt(raw[88192+(idx-1)*32:88192+idx*32])
  if not name:break
  row=raw[at:at+32]
  tx,rx=struct.unpack_from('<II',row)
  mode={0x14:'Digital',0x17:'Analog'}.get(row[8]);
  if not mode or not name:raise ValueError(f'Invalid channel #{idx}')
  contact=contacts.get(row[24]) if mode=='Digital' else None
  if mode=='Digital' and row[24] and contact is None:raise ValueError(f'Invalid TX contact index #{idx}')
  rx_tone=unpack_tone(row[16:18]) if mode=='Analog' else ('','')
  tx_tone=unpack_tone(row[18:20]) if mode=='Analog' else ('','')
  channels.append({'channel_number':idx,'channel_alias':name,'mode':mode,
   'tx_mhz':round(tx/1e6,6),'rx_mhz':round(rx/1e6,6),
   'tx_contact_id':contact['id'] if contact else None,
   'tx_contact_name':contact['name'] if contact else '',
   'color_code':row[16]&15 if mode=='Digital' else None,
   'slot':2 if row[16]&16 else 1 if mode=='Digital' else None,
   'rx_only':bool(row[9]&2),'rx_tone_type':rx_tone[0], 'rx_tone':rx_tone[1],
   'tx_tone_type':tx_tone[0], 'tx_tone':tx_tone[1],
   'rx_group_number':row[22] if mode=='Digital' else 0,
   'auto_scan':bool(row[9]&1),
   'auto_roam_candidate':mode=='Digital' and row[17]==44,
   'list_index':struct.unpack_from('<H',row,12)[0]})
 # Variable populated zones, 80-byte records with 16 channel indices at +48.
 zones=[]
 for zid in range(64):
  at=152192+80*zid; name=u16txt(raw[at:at+32]); n=raw[at+36]
  if not name:break
  if not name or not 1<=n<=16:raise ValueError(f'Corrupt zone record #{zid+1}')
  indexes=list(struct.unpack_from('<16H',raw,at+48))[:n]
  if any(not 1<=i<=len(channels) for i in indexes):raise ValueError(f'Zone channel index out of range: {name}')
  zones.append({'name':name,'ids':indexes})
 if len({z['name'] for z in zones})!=len(zones):raise ValueError('Duplicate source zone names')
 # First 4 bytes: member count. Alias at +4 (UTF-16LE, 32-byte slot),
 # contact indices at +36 (uint16).
 rxat=58784; qty=struct.unpack_from('<I',raw,rxat)[0]
 rxname=u16txt(raw[rxat+4:rxat+36])
 rxids=list(struct.unpack_from('<24H',raw,rxat+36))[:qty]
 if not 1<=qty<=24 or any(i not in contacts for i in rxids):
  raise ValueError('Cannot validate RX group members in current RDB')
 # The previous parser INCORRECTLY treated these as two-tone aliases.
 # They are the CS711 radio alias and power-on message, respectively.
 radio_alias=u16txt(raw[RADIO_ALIAS_OFFSET:RADIO_ALIAS_OFFSET+32])
 power_on_message=u16txt(raw[POWER_ON_MESSAGE_OFFSET:POWER_ON_MESSAGE_OFFSET+32])
 # Actual fixed-length CS711 2Tone Decode Def table (16 x 8 bytes):
 # little-endian uint16 Tone1/10, uint16 Tone2/10, uint16 type+flags,
 # uint16 additional flags. Source CPS has autogenerated names Decode Def 1...16.
 # 0x0126 = two-tone (CPS Two Tone); 0x0122 = single long tone (CPS Long Tone).
 # For Long Tone the second raw frequency is a disabled/unused UI field.
 decode_defs=[]
 for i in range(TWO_TONE_DEFS_CAPACITY):
  offset=TWO_TONE_DEFS_OFFSET+i*TWO_TONE_DEF_SIZE
  tone1,tone2,kind,flags=struct.unpack_from('<HHHH',raw,offset)
  if (tone1,tone2,kind,flags)==(0,0,0,0):continue
  if kind not in (0x0126,0x0122):
   raise ValueError(f'Unsupported 2Tone Decode Def #{i+1}: type=0x{kind:04X} raw={raw[offset:offset+8].hex()}')
  if flags!=0x0300:
   raise ValueError(f'Unrecognized 2Tone Decode Def #{i+1} flags=0x{flags:04X}; refusing silent loss')
  if not 2000<=tone1<=25000 or (kind==0x0126 and not 2000<=tone2<=25000):
   raise ValueError(f'2Tone Decode Def #{i+1} has out-of-range frequency')
  decode_defs.append({'index':i+1,'name':f'Decode Def {i+1}',
   'source_call_format':'Two Tone' if kind==0x0126 else 'Long Tone',
   'format':'A-B' if kind==0x0126 else 'A-B/Long C',
   'source_tone_1_hz':tone1/10,'source_tone_2_hz':tone2/10,
   'tone_a_hz':tone1/10 if kind==0x0126 else LONG_C_DUMMY_A_HZ,
   'tone_b_hz':tone2/10 if kind==0x0126 else LONG_C_DUMMY_B_HZ,
   'tone_c_hz':None if kind==0x0126 else tone1/10,
   'dummy_ab':kind==0x0122,'source_rdb_offset':offset,
   'raw_record_hex':raw[offset:offset+8].hex(),'raw_kind':f'0x{kind:04X}',
   'raw_flags':f'0x{flags:04X}'})
 if not decode_defs:raise ValueError('No populated CS711 two-tone definitions in source RDB')
 two_tone={'radio_alias':radio_alias,'power_on_message_unmapped':power_on_message,
   'decode_definitions':decode_defs,
   'decode_definition_count':len(decode_defs),
   'source_two_tone_system_settings_raw_hex':raw[254976:255232].hex(),
   'source_two_tone_general_settings_raw_hex':raw[255232:255264].hex(),
   'source_two_tone_system_note':'The source Analog > 2Tone > System contains CPS service settings. The populated decode definitions map to individual Motorola QCII Systems and linked Contacts. Unmapped service/alert/recording flags are retained in this audit, not claimed as converted.',
   'source_locations':{'radio_alias':RADIO_ALIAS_OFFSET,
     'power_on_message':POWER_ON_MESSAGE_OFFSET,
     'two_tone_definitions':TWO_TONE_DEFS_OFFSET}}
 return channels,contacts,zones,{'name':rxname,'contact_indexes':rxids},two_tone

def build(source,target,output,overwrite=False,profile=None):
 for path in (source,target):
  if not path.exists():raise ValueError(f'Missing: {path}')
 if output.resolve() in (source.resolve(),target.resolve()):raise ValueError('Output must not overwrite input')
 generated_paths=[output]+[output.with_suffix(x) for x in (
  '.qa.json','.channels.csv','.zones-verified.csv',
  '.2tone-verified.csv','.2tone-source-audit.json')]
 if any(p.resolve() in (source.resolve(),target.resolve()) for p in generated_paths):
  raise ValueError('Generated file name would overwrite source or target')
 conflicts=[str(p) for p in generated_paths if p.exists()]
 if conflicts and not overwrite:
  raise ValueError('Generated file(s) already exist; use --force: '+', '.join(conflicts))
 req=profile if profile is not None else load_profile(None)
 src, contacts, source_zones, source_rx_group, two_tone = read_live_rdb(source)
 if not src:raise ValueError('RDB contains no populated channels')
 if len({c['channel_alias'] for c in src})!=len(src):
  raise ValueError('Duplicate source channel names are not currently supported')
 if req.get('expected_source_channels') is not None and len(src)!=req['expected_source_channels']:
  raise ValueError('Source channel count differs from profile expectation')
 if req.get('expected_two_tone_count') is not None and len(two_tone['decode_definitions'])!=req['expected_two_tone_count']:
  raise ValueError('Two-tone definition count differs from profile expectation')
 byname={x['channel_alias']:x for x in src}
 excluded=set(req['exclude_exact_channel_names'])
 rules={int(x['channel_number']):x for x in req['channel_rules']}
 for rl in req['roam_lists']:
  for item in rl['members']:
   num=int(item['source_channel_number'])
   if not 1<=num<=len(src):raise ValueError('Bad roam source channel number')
   c=src[num-1]
   if c['channel_alias']!=item['name'] or c['tx_contact_id']!=rl['required_talkgroup_id']:
    raise ValueError('Source roaming list mismatch: '+item['name'])
 for sl in req['scan_lists']:
  for item in sl['members']:
   if item.get('source_channel_number') is None:continue
   num=int(item['source_channel_number'])
   if not 1<=num<=len(src):raise ValueError('Bad scan source channel number')
   if src[num-1]['channel_alias']!=item['name']:
    raise ValueError('Source scan list mismatch: '+item['name'])
 corrections={}
 for key,change in req['frequency_corrections'].items():
  num=int(key)
  if not 1<=num<=len(src):raise ValueError('Bad TX correction source index: '+key)
  tx=float(change['tx_mhz'])
  if not 0<tx<=1000:raise ValueError('Bad TX correction frequency: '+key)
  corrections[num]=(tx,change.get('reason','Explicit profile TX override'))
 for num,(tx,reason) in corrections.items():src[num-1]['tx_mhz']=tx
 # No inferred scan/roam lists: require complete mapping if source references them.
 scan_index_map={int(k):v for k,v in req['source_scan_list_index_map'].items()}
 roam_tg_map={int(k):v for k,v in req['roam_list_by_talkgroup'].items()}
 for rec in src:
  if rec['auto_roam_candidate'] and rec['tx_contact_id'] not in roam_tg_map:
   raise ValueError('RDB uses auto roaming but profile lacks roam_list_by_talkgroup for TG '+str(rec['tx_contact_id']))
  if not rec['auto_roam_candidate'] and rec['list_index'] not in (0,65535) and rec['list_index'] not in scan_index_map:
   raise ValueError('RDB uses scan list index '+str(rec['list_index'])+'; supply --profile with source_scan_list_index_map')
 prefix,header,inner,mx=parse_archive(target.read_bytes())
 db,regex=get_dbnode(mx)
 base=next((x for x in db if x.get(XSI)=='Record'),None)
 if base is None:raise ValueError('Missing DBNode root record')
 groups={x.get('Name'):x for x in base if x.get(XSI)=='RefSet'}
 required=['ConventionalPersonality','PCRContacts','Zone','ScanItems','RoamList']
 if not all(x in groups for x in required):raise ValueError('Missing CPS2 database collection')
 personality=groups['ConventionalPersonality'];zone=groups['Zone'];scan=groups['ScanItems'];roam=groups['RoamList'];contact_group=groups['PCRContacts']
 existing_cp=records(personality);original_count=len(existing_cp)
 if req.get('expected_original_personalities') is not None and original_count!=req['expected_original_personalities']:
  raise ValueError('Original target personality count differs from profile expectation')
 if not existing_cp:raise ValueError('Target has no channel templates')
 old_channel_snapshot={r.get('UUID'):ET.tostring(r) for r in existing_cp}
 old_zone_snapshot={r.get('UUID'):ET.tostring(r) for r in records(zone)}
 old_contact_snapshot={r.get('UUID'):ET.tostring(r) for r in records(contact_group)}
 # Optional exclusion rules apply to all scan list memberships,
 # but never remove channel personalities.
 existing_names_by_uuid={r.get('UUID'):fdict(r)['CP_CNVPERSALIAS'] for r in existing_cp}
 original_zone_item_names={}
 for old_zone in records(zone):
  old_items=next(x for x in old_zone if x.get('Name')=='ZoneItems')
  for zi in records(old_items):
   original_zone_item_names[zi.get('UUID')]=existing_names_by_uuid[fdict(zi)['ZP_PERSIT']]
 existing_scan_removals=[]
 for old_scan in records(scan):
  list_name=fdict(old_scan)['SP_SCANLISTALIAS']
  old_items=next(x for x in old_scan if x.get('Name')=='ScanListItems')
  for member in list(records(old_items)):
   linked_alias=original_zone_item_names.get(fdict(member)['SP_CNVPERCOMP'])
   if linked_alias in excluded:
    existing_scan_removals.append({'scan_list':list_name,'excluded_channel':linked_alias,'zone_item_uuid':fdict(member)['SP_CNVPERCOMP']})
    old_items.remove(member)
  reindex(old_items)
 old_scan_snapshot={r.get('UUID'):ET.tostring(r) for r in records(scan)}
 analog_template=next(r for r in existing_cp if fdict(r)['CP_PERSTYPE']=='ANLGCONV' and fdict(r)['CP_RXONLYEN']=='False')
 digital_template=next(r for r in existing_cp if fdict(r)['CP_PERSTYPE'].startswith('DGTL') and fdict(r)['CP_UKPPERS']!='NONE')
 contact_template=next((c for c in records(contact_group) if any(
   fdict(call).get('DU_CALLTYPE')=='GRPCALL'
   for sub in c if sub.get('Name')=='DigitalCalls' for call in records(sub))),None)
 if contact_template is None:raise ValueError('Target has no group-call contact template')
 zo_template=next(z for z in records(zone) if fdict(z)['ZP_ZONETYPE']=='NORMAL')
 zi_template=records(next(x for x in zo_template if x.get('Name')=='ZoneItems'))[0]
 scan_template=records(scan)[0]
 scan_item_template=records(next(x for x in scan_template if x.get('Name')=='ScanListItems'))[0]
 roam_template=records(roam)[0]
 roam_item_template=records(next(x for x in roam_template if x.get('Name')=='RoamListItems'))[0]
 # Contact IDs are the only authoritative mapping for digital TX contact.
 contact_by_id={}
 for c in records(contact_group):
  for dc in c:
   if dc.get('Name')=='DigitalCalls':
    for call in records(dc):
     k=fdict(call)
     if k.get('DU_CALLTYPE')=='GRPCALL' and k.get('DU_CALLLSTID'):contact_by_id[int(k['DU_CALLLSTID'])]=c.get('UUID')
 new_contacts=[]
 for original in contacts.values():
  tg=original['id']
  if tg in contact_by_id:continue
  item=clone_record(contact_template,len(records(contact_group)))
  set_field(item,'ContactName',original['name'])
  dc=next(x for x in item if x.get('Name')=='DigitalCalls')
  call=records(dc)[0]
  set_field(call,'DU_CALLLSTID',tg)
  contact_group.append(item)
  contact_by_id[tg]=item.get('UUID')
  new_contacts.append({'name':original['name'],'talkgroup_id':tg,'uuid':item.get('UUID')})
 reindex(contact_group)
 # RX Group: create a target list with the source RDB member IDs.
 rx_group_collection=groups.get('DigitalRXGroupList')
 if rx_group_collection is None:raise ValueError('Target missing DigitalRXGroupList')
 rx_template=records(rx_group_collection)[0]
 itemset=next(g for g in rx_template if g.get('Name')=='DigitalRXGroupListItems')
 item_template=records(itemset)[0]
 rx_group=clone_record(rx_template,len(records(rx_group_collection)))
 set_field(rx_group,'RXTG_RXTGLISTALIAS',source_rx_group['name'])
 rxitems=next(g for g in rx_group if g.get('Name')=='DigitalRXGroupListItems')
 for old in list(records(rxitems)):rxitems.remove(old)
 for i in source_rx_group['contact_indexes']:
  tg=contacts[i]['id']; ct=contact_by_id.get(tg)
  if not ct:raise ValueError('RX-group contact ID missing: '+str(tg))
  new_item=clone_record(item_template,len(records(rxitems)))
  set_field(new_item,'RXTG_DGUCLCOMP',ct,refer='PCRContacts')
  rxitems.append(new_item)
 reindex(rxitems);rx_group_collection.append(rx_group);reindex(rx_group_collection)
 rx_group_uuid=rx_group.get('UUID')
 # The source radio alias is NOT a QCII definition, and the startup
 # message has no R7 counterpart. Map the radio alias where CPS supports it.
 general=records(groups['GeneralSettings'])
 if len(general)!=1:raise ValueError('R7 GeneralSettings record not found')
 radio_alias=two_tone['radio_alias']
 if radio_alias:
  for fn in ('RC_RADIOALIAS_CPS','SURC_ALIASNAME_CPS'):
   set_field(general[0],fn,radio_alias)
 # Existing target QCII system modifications are explicit profile choices.
 qcii_system_group=groups['QuikCallIISystems']
 original_qcii_systems=records(qcii_system_group)
 staged_qcii=[]
 for alias in req['existing_qcii_ab_systems']:
  matches=[x for x in original_qcii_systems if fdict(x).get('QCIISYS_QCIISYSALIAS')==alias]
  if len(matches)!=1:raise ValueError('QCII target system not uniquely found: '+alias)
  rec=matches[0]
  old=fdict(rec)
  set_field(rec,'QCIISYS_FORMATTYPE','CALLFMT_AB')
  staged_qcii.append({'system_alias':alias,'previous_format':old['QCIISYS_FORMATTYPE'],
    'new_format':'CALLFMT_AB','tone_a_hz':float(old['QCIISYS_TONEARF']),
    'tone_b_hz':float(old['QCIISYS_TONEBRF'])})
 qcii_template=original_qcii_systems[0] if original_qcii_systems else None
 if qcii_template is None:raise ValueError('Target has no QCII system template')
 # Only use a QCII contact as a cloning template; never select by a personal name.
 qc_contact_template=next((copy.deepcopy(c) for c in records(contact_group)
   if any(sub.get('Name')=='QuikCallIICalls' and len(records(sub))==1 for sub in c)),None)
 if qc_contact_template is None:raise ValueError('Target has no linked QCII contact template')
 new_qcii=[]
 # Create one Motorola Quick-Call II system for each *populated source*
 # decode definition, and one explicitly linked QCII contact. NO fixed
 # frequency inserts: only documented dummy A/B for Long C.
 for sd in two_tone['decode_definitions']:
  sysrec=clone_record(qcii_template,len(records(qcii_system_group)))
  set_field(sysrec,'QCIISYS_QCIISYSALIAS',sd['name'])
  set_field(sysrec,'QCIISYS_CALLTYPE','SELECTIVE_CALL')
  set_field(sysrec,'QCIISYS_FORMATTYPE','CALLFMT_AB_LONG_C' if sd['dummy_ab'] else 'CALLFMT_AB')
  qcii_field_pair(sysrec,'QCIISYS_TONEARF',sd['tone_a_hz'],'QCIISYS_CODEA',source_name=sd['name'])
  qcii_field_pair(sysrec,'QCIISYS_TONEBRF',sd['tone_b_hz'],'QCIISYS_CODEB',source_name=sd['name'])
  if sd['dummy_ab']:
   qcii_field_pair(sysrec,'QCIISYS_TONECRF',sd['tone_c_hz'],'QCIISYS_CODEC',source_name=sd['name'])
  sysrec.set('Comments','Imported dynamically from CS711 RDB '+sd['name']+(' (Long C; A/B user-approved dummy frequencies)' if sd['dummy_ab'] else ' (A-B)'))
  qcii_system_group.append(sysrec)
  contact=clone_record(qc_contact_template,len(records(contact_group)))
  set_field(contact,'ContactName',sd['name'])
  calls=next(x for x in contact if x.get('Name')=='QuikCallIICalls')
  if len(records(calls))!=1:raise ValueError('Unexpected QCII contact template layout')
  call=records(calls)[0]
  set_field(call,'QU_QCIISYS',sysrec.get('UUID'),refer='QuikCallIISystems')
  set_field(call,'QU_CALLFORMAT','TWO_TONE')
  qcii_field_pair(call,'QU_TONEATXFRE',sd['tone_a_hz'],'QU_CODEA',source_name=sd['name'])
  qcii_field_pair(call,'QU_TONEBTXFRE',sd['tone_b_hz'],'QU_CODEB',source_name=sd['name'])
  contact.set('Comments','Imported dynamically from CS711 RDB '+sd['name'])
  contact_group.append(contact)
  new_qcii.append({'source_index':sd['index'],'name':sd['name'],'format':sd['format'],
    'source_format':sd['source_call_format'],'tone_a_hz':sd['tone_a_hz'],
    'tone_b_hz':sd['tone_b_hz'],'tone_c_hz':sd['tone_c_hz'],
    'synthetic_ab':sd['dummy_ab'],'system_uuid':sysrec.get('UUID'),
    'contact_uuid':contact.get('UUID')})
 reindex(qcii_system_group)
 reindex(contact_group)
 # Append every CS channel. They are NEVER removed even if excluded from lists.
 inserted={};added=[]
 for rec in src:
  num=rec['channel_number'];name=rec['channel_alias']
  templ=digital_template if rec['mode']=='Digital' else analog_template
  ch=clone_record(templ,len(records(personality)))
  set_field(ch,'CP_CNVPERSALIAS',name)
  set_field(ch,'CP_TXFREQ',format(rec['tx_mhz'],'.6f').rstrip('0').rstrip('.'))
  set_field(ch,'CP_RXFREQ',format(rec['rx_mhz'],'.6f').rstrip('0').rstrip('.'))
  if rec['mode']=='Digital':
   set_field(ch,'CP_COLORCODE',rec['color_code'])
   set_field(ch,'CP_SLTASSGMNT','SLOT'+str(rec['slot']))
   tg=rec['tx_contact_id']
   set_field(ch,'CP_UKPPERS',contact_by_id[tg] if tg is not None else 'NONE',refer='PCRContacts' if tg is not None else '')
  else:
   set_field(ch,'CP_UKPPERS','NONE')
  if rec['mode']=='Analog':
   set_field(ch,'CP_XSQCHTY',rec['rx_tone_type'])
   set_field(ch,'CP_TXSQCHTY',rec['tx_tone_type'])
   for direction in ('rx','tx'):
    ttype=rec[direction+'_tone_type'];tone=rec[direction+'_tone']
    if ttype=='DPL':set_field(ch,'CP_RXDPLCD' if direction=='rx' else 'CP_TXTDPLCD',tone)
    if ttype=='TPL':tpl_field_pair(ch,direction,tone,source_name=name)
  if rec['mode']=='Digital':
   if rec['rx_group_number']:
    if rec['rx_group_number']!=1:raise ValueError('Unexpected source RX group number')
    set_field(ch,'CP_TGLISTIT',rx_group_uuid,refer='DigitalRXGroupList')
   else:set_field(ch,'CP_TGLISTIT','NONE')
  set_field(ch,'CP_RXONLYEN','True' if rec['rx_only'] else 'False')
  set_field(ch,'CP_RXONLY','True' if rec['rx_only'] else 'False')
  apply_imported_admit_criteria(ch,rec)
  set_field(ch,'CP_UTOSCANEN','False')
  set_field(ch,'CP_SCNROAMLISTIT','NONE')
  personality.append(ch)
  inserted[num]=ch
  added.append({'source_number':num,'name':name,'mode':rec['mode'],'rx_mhz':rec['rx_mhz'],'tx_mhz':rec['tx_mhz'],
                'tx_contact_id':rec['tx_contact_id'],'uuid':ch.get('UUID'),'rx_only':rec['rx_only'],'rx_tone_type':rec['rx_tone_type'],'rx_tone':rec['rx_tone'],'tx_tone_type':rec['tx_tone_type'],'tx_tone':rec['tx_tone'],'rx_group':source_rx_group['name'] if rec['rx_group_number']==1 else '', 'list_index':rec['list_index'],'auto_scan':rec['auto_scan'],'roam_source':rec['auto_roam_candidate']})
 reindex(personality)
 assert len(records(personality))==original_count+len(src)
 # IMPORTANT: Motorola CPS will silently DUPLICATE a personality if the
 # SAME UUID is referenced by more than one zone item. Its autogenerated copy
 # gets a default alias (Channel166, Channel167, ...), losing the programming.
 # Source channels may appear in multiple zones.
 # We must create and program those nine additional personalities OURSELVES.
 # Never reuse a personality UUID across two imported ZoneItems.
 channel_instances={num:[rec] for num,rec in inserted.items()}
 first_assignment=set()
 expected_zone_assignments={}
 zoneitem_lookup={}
 new_zones=[]
 zonedef=[dict(z) for z in source_zones]
 existing_zone_aliases={fdict(z)['ZP_ZONEALIAS'] for z in records(zone)}
 for z in zonedef:
  if z['name'] in existing_zone_aliases:
   proposed=z['name']+' CS711'
   if len(proposed)>16:raise ValueError('Zone alias collision cannot be resolved: '+z['name'])
   z['name']=proposed
  if len(z['name'])>16:raise ValueError('Imported zone alias >16 characters: '+z['name'])
 assigned={i for z in source_zones for i in z['ids']}
 orphans=[i for i in range(1,len(src)+1) if i not in assigned]
 for start in range(0,len(orphans),16):
  zonedef.append({'name':'Unassigned CS '+str(1+start//16),'ids':orphans[start:start+16]})
 for z in zonedef:
  zn=clone_record(zo_template,len(records(zone)))
  zname=z['name'];set_field(zn,'ZP_ZONEALIAS',zname)
  znitems=next(x for x in zn if x.get('Name')=='ZoneItems')
  for item in list(records(znitems)):znitems.remove(item)
  expected_zone_assignments[zn.get('UUID')]=[]
  for idx in z['ids']:
   rec=src[idx-1]
   if idx not in first_assignment:
    channel=inserted[idx]
    first_assignment.add(idx)
   else:
    # Complete copy of the source channel programming, not a CPS-created
    # default ChannelNNN placeholder. Later scan/roam rules apply to ALL copies.
    channel=clone_record(inserted[idx],len(records(personality)))
    personality.append(channel)
    channel_instances[idx].append(channel)
   item=clone_record(zi_template,len(records(znitems)))
   set_field(item,'ZP_PERSIT',channel.get('UUID'),refer='ConventionalPersonality')
   znitems.append(item)
   expected_zone_assignments[zn.get('UUID')].append((idx,channel.get('UUID')))
   # Use the FIRST full assignment for scan/roam membership references.
   if rec['channel_alias'] not in zoneitem_lookup:
    zoneitem_lookup[rec['channel_alias']]={'zone_uuid':zn.get('UUID'),'item_uuid':item.get('UUID'),
       'channel_uuid':channel.get('UUID')}
  reindex(znitems);zone.append(zn)
  new_zones.append({'name':zname,'channels':len(records(znitems)),'uuid':zn.get('UUID')})
 reindex(zone);reindex(personality)
 assert len(zoneitem_lookup)==len(src)
 assert first_assignment==set(range(1,len(src)+1)), 'A source channel was never placed in any zone'
 imported_zone_positions=sum(len(z['ids']) for z in zonedef)
 imported_instances=sum(map(len,channel_instances.values()))
 assert imported_zone_positions==imported_instances
 assert len(records(personality))==original_count+imported_instances
 assert len({node.get('UUID') for group in channel_instances.values() for node in group})==imported_instances
 assert len({uuid for assignments in expected_zone_assignments.values() for _,uuid in assignments})==imported_instances
 if req.get('expected_imported_zone_positions') is not None and imported_zone_positions!=req['expected_imported_zone_positions']:
  raise ValueError('Imported zone-position count differs from profile expectation')
 # Scan lists: Selected is the Motorola SP_DSGTXMEM pseudomember, not a physical row.
 scan_uuid={}
 for s in req['scan_lists']:
  names=[x['name'] for x in s['members']]
  if names[0]!='Selected' or len(names)!=len(set(names)) or len(names)>16:raise ValueError('Invalid scan member list')
  if any(n in excluded for n in names):raise ValueError('Excluded scan member')
  sc=clone_record(scan_template,len(records(scan)))
  set_field(sc,'SP_SCANLISTALIAS',s['name'])
  set_field(sc,'SP_DSGTXMEM','SELECTED')
  si=next(x for x in sc if x.get('Name')=='ScanListItems')
  for old in list(records(si)):si.remove(old)
  for name in names[1:]:
   ref=zoneitem_lookup[name]
   item=clone_record(scan_item_template,len(records(si)))
   set_field(item,'SP_CNVPERCOMP_Zone',ref['zone_uuid'],refer='Zone')
   set_field(item,'SP_CNVPERCOMP',ref['item_uuid'],refer='ZoneItems')
   si.append(item)
  reindex(si)
  scan.append(sc);scan_uuid[s['name']]=sc.get('UUID')
 reindex(scan)
 # Reuse existing target roam lists only when the private profile requests it.
 existing_roams={fdict(x)['SSP_SCANLISTALIAS']:x for x in records(roam)}
 roam_map={}
 for rl in req['roam_lists']:
  label=rl['name']
  reuse=req['remap_existing_roam_lists'].get(label)
  if reuse:
   if reuse not in existing_roams:raise ValueError('Cannot remap missing target roam list: '+reuse)
   node=existing_roams[reuse]
  else:
   node=clone_record(roam_template,len(records(roam)))
   roam.append(node)
  roam_map[label]=node
 roam_uuid={}
 for rl in req['roam_lists']:
  name=rl['name'];tg=rl['required_talkgroup_id'];node=roam_map[name]
  set_field(node,'SSP_SCANLISTALIAS',name)
  set_field(node,'SSP_DSGTXMEMTYPE','SELECTED')
  set_field(node,'SSP_PLLOCKCHMARKEN','False')
  members=next(x for x in node if x.get('Name')=='RoamListItems')
  for old in list(records(members)):members.remove(old)
  for member in rl['members']:
   name_ch=member['name']
   if name_ch in excluded:raise ValueError('Excluded roaming member')
   if byname[name_ch]['tx_contact_id']!=tg:raise ValueError('TG mismatch '+name+':'+name_ch)
   rref=zoneitem_lookup[name_ch]
   item=clone_record(roam_item_template,len(records(members)))
   set_field(item,'SSP_CNVPERCOMP_Zone',rref['zone_uuid'],refer='Zone')
   set_field(item,'SSP_CNVPERCOMP',rref['item_uuid'],refer='ZoneItems')
   members.append(item)
  reindex(members)
  roam_uuid[name]=node.get('UUID')
 reindex(roam)
 # Restore the scan/roam list assignment on EVERY channel, not just the
 # two Auto Scan channels! List membership and channel assignment are separate.
 for rec in src:
  idx=rec['list_index']
  for ch in channel_instances[rec['channel_number']]:
   if rec['auto_roam_candidate']:
    tg=rec['tx_contact_id']
    label=roam_tg_map[tg]
    if label not in roam_uuid:raise ValueError('Missing configured roaming list: '+label)
    set_field(ch,'CP_SCNROAMLISTIT',roam_uuid[label],refer='RoamList')
   elif idx in scan_index_map:
    label=scan_index_map[idx]
    if label not in scan_uuid:raise ValueError('Missing configured scan list: '+label)
    set_field(ch,'CP_SCNROAMLISTIT',scan_uuid[label],refer='ScanItems')
   elif idx in (0,65535):
    set_field(ch,'CP_SCNROAMLISTIT','NONE')
   else:raise ValueError('Unrecognized source scan/roam index: '+str(idx))
   if rec['auto_scan']:
    if rec['auto_roam_candidate']:raise ValueError('Source channel has both Auto Scan and roaming')
    set_field(ch,'CP_UTOSCANEN','True')
 # Independently set requested per-channel behaviors. No automatic scan on roaming channels.
 for num,rule in rules.items():
  for target_channel in channel_instances[num]:
   assert fdict(target_channel)['CP_CNVPERSALIAS']==rule['name']
   if 'auto_scan' in rule:
    assert rule.get('member_of_scan_list') is False
    set_field(target_channel,'CP_UTOSCANEN','True')
    set_field(target_channel,'CP_SCNROAMLISTIT',scan_uuid[rule['scan_list']],refer='ScanItems')
   else:
    assert rule['tx_contact_id']==byname[rule['name']]['tx_contact_id']
    set_field(target_channel,'CP_UTOSCANEN','False')
    set_field(target_channel,'CP_SCNROAMLISTIT',roam_uuid[rule['roaming_list']],refer='RoamList')
 # Do not remove any source channels; exclusions apply solely to list membership.
 for keep in req['must_keep_channel_names']:
  assert keep in zoneitem_lookup, f'Missing imported channel: {keep}'
 for uuid_,orig in old_channel_snapshot.items():
  assert ET.tostring(next(r for r in records(personality) if r.get('UUID')==uuid_))==orig, f'Existing channel mutated: {uuid_}'
 for uuid_,orig in old_zone_snapshot.items():
  assert ET.tostring(next(r for r in records(zone) if r.get('UUID')==uuid_))==orig, f'Existing zone mutated: {uuid_}'
 for uuid_,orig in old_contact_snapshot.items():
  assert ET.tostring(next(r for r in records(contact_group) if r.get('UUID')==uuid_))==orig, f'Existing contact mutated: {uuid_}'
 for uuid_,orig in old_scan_snapshot.items():
  assert ET.tostring(next(r for r in records(scan) if r.get('UUID')==uuid_))==orig, f'Existing scan list mutated: {uuid_}'
 # All GUIDs unique and all imported list references valid.
 ids=[e.get('UUID') for e in db.iter('DBNode') if e.get(XSI)=='Record']
 if len(ids)!=len(set(ids)):raise ValueError('Duplicate DBNode record UUID')
 zids={v['zone_uuid'] for v in zoneitem_lookup.values()};items={v['item_uuid'] for v in zoneitem_lookup.values()}
 for groupname,itemname,field_zone,field_item in [('ScanItems','ScanListItems','SP_CNVPERCOMP_Zone','SP_CNVPERCOMP'),
                                                ('RoamList','RoamListItems','SSP_CNVPERCOMP_Zone','SSP_CNVPERCOMP')]:
  for lst in records(groups[groupname]):
   sub=next(x for x in lst if x.get('Name')==itemname)
   for itm in records(sub):
    f=fdict(itm)
    if lst.get('UUID') in list(scan_uuid.values())+list(roam_uuid.values()):
     if f[field_zone] not in zids or f[field_item] not in items:raise ValueError('New list contains invalid zone item ref')
 # Encode inner XML and substitute ONLY the DBNodeCmpBytes text in untouched outer XML.
 dbbytes=b'\xef\xbb\xbf'+ET.tostring(db,encoding='utf-8',xml_declaration=True)
 packed=raw_compress(dbbytes)
 match=regex.search(mx)
 newbase=base64.b64encode(packed)
 newxml=mx[:match.start(2)]+newbase+mx[match.end(2):]
 output_bytes=encode_archive(prefix,header,inner,newxml)
 # Decode the complete newly built file, verify SHA256 and reexpand DBNode.
 _p,_h,_i,round_xml=parse_archive(output_bytes)
 if round_xml!=newxml:raise ValueError('New archive XML round-trip mismatch')
 checkdb,_=get_dbnode(round_xml)
 checkbase=next(x for x in checkdb if x.get(XSI)=='Record')
 ck={x.get('Name'):x for x in checkbase if x.get(XSI)=='RefSet'}
 counts={name:len(records(ck[name])) for name in ('ConventionalPersonality','Zone','ScanItems','RoamList','PCRContacts','DigitalRXGroupList','QuikCallIISystems')}
 assert counts['ConventionalPersonality']==original_count+imported_instances
 assert counts['Zone']==len(old_zone_snapshot)+len(new_zones)
 assert counts['ScanItems']==len(old_scan_snapshot)+len(req['scan_lists'])
 assert counts['RoamList']==len(existing_roams)+sum(rl['name'] not in req['remap_existing_roam_lists'] for rl in req['roam_lists'])
 assert counts['DigitalRXGroupList']==len(records(rx_group_collection))
 assert counts['QuikCallIISystems']==len(original_qcii_systems)+len(new_qcii)
 assert len(records(ck['PCRContacts']))==len(old_contact_snapshot)+len(new_contacts)+len(new_qcii)
 assert all(fdict(x).get('ContactName') not in (two_tone['radio_alias'],two_tone['power_on_message_unmapped'])
            for x in records(ck['PCRContacts']) if x.get('UUID') not in old_contact_snapshot)
 assert all(fdict(x)['QCIISYS_QCIISYSALIAS'] not in (two_tone['radio_alias'],two_tone['power_on_message_unmapped'])
            for x in records(ck['QuikCallIISystems']))
 verify_general=fdict(records(ck['GeneralSettings'])[0])
 assert verify_general['RC_RADIOALIAS_CPS']==radio_alias
 assert verify_general['SURC_ALIASNAME_CPS']==radio_alias
 for info in staged_qcii:
  node=next(x for x in records(ck['QuikCallIISystems'])
    if fdict(x)['QCIISYS_QCIISYSALIAS']==info['system_alias'])
  nf=fdict(node)
  assert nf['QCIISYS_FORMATTYPE']=='CALLFMT_AB'
  assert float(nf['QCIISYS_TONEARF'])==info['tone_a_hz']
  assert float(nf['QCIISYS_TONEBRF'])==info['tone_b_hz']
 # Verify each imported QCII pair after XCTB re-decrypt/decompress and UUID
 # resolution. No alias-based shortcut or source hardcoded frequencies.
 actual_systems={r.get('UUID'):r for r in records(ck['QuikCallIISystems'])}
 actual_contacts={r.get('UUID'):r for r in records(ck['PCRContacts'])}
 assert len(new_qcii)==len(two_tone['decode_definitions'])
 verified_tones=[]  # Built-in source-to-reopened-XCTB audit; no companion script needed.
 for sd,created in zip(two_tone['decode_definitions'],new_qcii):
  sysfields=fdict(actual_systems[created['system_uuid']])
  confields=fdict(actual_contacts[created['contact_uuid']])
  assert confields['ContactName']==sd['name']
  assert sysfields['QCIISYS_QCIISYSALIAS']==sd['name']
  assert sysfields['QCIISYS_CALLTYPE']=='SELECTIVE_CALL'
  assert sysfields['QCIISYS_FORMATTYPE']==('CALLFMT_AB_LONG_C' if sd['dummy_ab'] else 'CALLFMT_AB')
  for hzkey,codekey,expected in [('QCIISYS_TONEARF','QCIISYS_CODEA',sd['tone_a_hz']),
                                  ('QCIISYS_TONEBRF','QCIISYS_CODEB',sd['tone_b_hz'])]:
   assert float(sysfields[hzkey])==expected
   assert sysfields[codekey]==QCII_TONE_CODES[expected]
  if sd['dummy_ab']:
   assert float(sysfields['QCIISYS_TONECRF'])==sd['tone_c_hz']
   assert sysfields['QCIISYS_CODEC']==QCII_TONE_CODES[sd['tone_c_hz']]
  calls=records(next(x for x in actual_contacts[created['contact_uuid']] if x.get('Name')=='QuikCallIICalls'))
  assert len(calls)==1
  ff=fdict(calls[0]);assert ff['QU_QCIISYS']==created['system_uuid']
  assert ff['QU_CALLFORMAT']=='TWO_TONE'
  assert float(ff['QU_TONEATXFRE'])==sd['tone_a_hz'] and ff['QU_CODEA']==QCII_TONE_CODES[sd['tone_a_hz']]
  assert float(ff['QU_TONEBTXFRE'])==sd['tone_b_hz'] and ff['QU_CODEB']==QCII_TONE_CODES[sd['tone_b_hz']]
  # Include both source raw values, including the intentionally INACTIVE second
  # long-tone frequency, to make mistakes obvious in the exported report.
  verified_tones.append({
   'index':sd['index'], 'name':sd['name'], 'source_rdb_offset':sd['source_rdb_offset'],
   'source_raw_hex':sd['raw_record_hex'], 'source_raw_kind':sd['raw_kind'],
   'source_call_format':sd['source_call_format'],
   'source_tone_1_hz':sd['source_tone_1_hz'],
   'source_tone_2_hz':sd['source_tone_2_hz'],
   'source_tone_2_active':not sd['dummy_ab'],
   'motorola_call_type':sysfields['QCIISYS_CALLTYPE'],
   'motorola_format':sd['format'],
   'motorola_tone_a_hz':float(sysfields['QCIISYS_TONEARF']),
   'motorola_tone_b_hz':float(sysfields['QCIISYS_TONEBRF']),
   'motorola_tone_c_hz':float(sysfields['QCIISYS_TONECRF']) if sd['dummy_ab'] else '',
   'motorola_tone_a_code':sysfields['QCIISYS_CODEA'],
   'motorola_tone_b_code':sysfields['QCIISYS_CODEB'],
   'motorola_tone_c_code':sysfields['QCIISYS_CODEC'] if sd['dummy_ab'] else '',
   'a_b_placeholder_only_for_long_c':sd['dummy_ab'],
   'quick_call_ii_system_uuid':created['system_uuid'],
   'linked_contact_uuid':created['contact_uuid'],
   'contact_link_verified':ff['QU_QCIISYS']==created['system_uuid'],
   'verification':'PASS',
  })
 assert len(verified_tones)==len(two_tone['decode_definitions'])
 assert all(row['verification']=='PASS' and row['contact_link_verified'] for row in verified_tones)
 assert all(fdict(r)['CP_CNVPERSALIAS'] in {a['name'] for a in added} for r in records(ck['ConventionalPersonality'])[original_count:])
 # Extra source-vs-output checks on every imported alias, mode, TX, RX, TG, scan/roam reference.
 # Independently resolve every Motorola digital contact UUID back to a TG ID.
 tg_from_contact_uuid={}
 for cc in records(ck['PCRContacts']):
  for sub in cc:
   if sub.get('Name')=='DigitalCalls':
    for cc_call in records(sub):
     cf=fdict(cc_call)
     if cf.get('DU_CALLLSTID') and cf.get('DU_CALLTYPE')=='GRPCALL':
      tg_from_contact_uuid[cc.get('UUID')]=int(cf['DU_CALLLSTID'])
 # Do not collapse duplicate channel aliases with a dictionary: each zone
 # occurrence is a separate fully-programmed Motorola personality.
 decoded_imported=records(ck['ConventionalPersonality'])[original_count:]
 actual_personality_by_uuid={ch.get('UUID'):fdict(ch) for ch in decoded_imported}
 imported_check={rec['channel_alias']:fdict(channel_instances[rec['channel_number']][0]) for rec in src}
 assert len(imported_check)==len(src) and len(actual_personality_by_uuid)==imported_instances
 # Every copy must match the source channel fields, not just the first copy.
 for rec in src:
  for channel in channel_instances[rec['channel_number']]:
   f=actual_personality_by_uuid[channel.get('UUID')]
   expected_primary=imported_check[rec['channel_alias']]
   assert f==expected_primary,('Programming mismatch in duplicate personality',rec['channel_alias'])
 for rec in src:
  f=imported_check[rec['channel_alias']]
  assert float(f['CP_TXFREQ'])==rec['tx_mhz'] and float(f['CP_RXFREQ'])==rec['rx_mhz']
  assert f['CP_PERSTYPE'].startswith('DGTL')==(rec['mode']=='Digital')
  assert f['CP_TXINHXPLEN']==('ONCHNNLFREE' if rec['rx_only'] else 'ALWAYS'),('Admit',rec['channel_alias'])
  if rec['mode']=='Digital':
   assert f['CP_MYCALLADCRTR']=='ALWAYS',('In Call Criteria',rec['channel_alias'])
   if rec['rx_only']:
    assert f['CP_GPSRVRTPERSIT']=='NONE',('GNSS/Data Revert',rec['channel_alias'])
    assert f['CP_GPSRVRTPERSIT_Zone']=='NONE'
    assert f['CP_DATAREVCHANLISTIT']=='NONE'
  if rec['mode']=='Digital':
   assert f['CP_SLTASSGMNT']=='SLOT'+str(rec['slot']) and int(f['CP_COLORCODE'])==rec['color_code']
   expected_tg=rec['tx_contact_id']
   if expected_tg is None:assert f['CP_UKPPERS']=='NONE'
   else:assert tg_from_contact_uuid[f['CP_UKPPERS']]==expected_tg,('TX contact mismatch',rec['channel_alias'])
 # Validate fresh zone names, assignments and RX group references after archive roundtrip.
 for z in source_zones:
  mapped=next(j for j in new_zones if j['name']==(z['name']+' CS711' if z['name'] in existing_zone_aliases else z['name']))
  zz=next(x for x in records(ck['Zone']) if x.get('UUID')==mapped['uuid'])
  actual=[fdict(x)['ZP_PERSIT'] for x in records(next(x for x in zz if x.get('Name')=='ZoneItems'))]
  expected=[uid for source_idx,uid in expected_zone_assignments[zz.get('UUID')]]
  assert actual==expected, ('Bad zone',z['name'])
  assert [actual_personality_by_uuid[uid]['CP_CNVPERSALIAS'] for uid in actual]==[src[i-1]['channel_alias'] for i in z['ids']], ('Zone position/alias mismatch',z['name'])
 verify_rx=next(g for g in records(ck['DigitalRXGroupList']) if g.get('UUID')==rx_group_uuid)
 ritems=records(next(x for x in verify_rx if x.get('Name')=='DigitalRXGroupListItems'))
 assert len(ritems)==len(source_rx_group['contact_indexes'])
 source_rx_tgs=[contacts[index]['id'] for index in source_rx_group['contact_indexes']]
 actual_rx_tgs=[tg_from_contact_uuid[fdict(it)['RXTG_DGUCLCOMP']] for it in ritems]
 assert actual_rx_tgs==source_rx_tgs, ('RX group contacts do not match source',actual_rx_tgs,source_rx_tgs)
 for rec in src:
  f=imported_check[rec['channel_alias']]
  if rec['mode']=='Digital':
   assert (f['CP_TGLISTIT']==rx_group_uuid)==(rec['rx_group_number']==1)
  assert (f['CP_UTOSCANEN']=='True')==rec['auto_scan'],('Auto Scan',rec['channel_alias'])
  if not rec['auto_roam_candidate']:
   if rec['list_index'] in scan_index_map:assert f['CP_SCNROAMLISTIT']==scan_uuid[scan_index_map[rec['list_index']]]
   if rec['list_index'] in (0,65535):assert f['CP_SCNROAMLISTIT']=='NONE'
  if rec['mode']=='Analog':
   assert f['CP_XSQCHTY']==rec['rx_tone_type'] and f['CP_TXSQCHTY']==rec['tx_tone_type']
   for side in ('rx','tx'):
    typ=rec[side+'_tone_type'];tone=rec[side+'_tone']
    if typ=='DPL':assert f['CP_RXDPLCD' if side=='rx' else 'CP_TXTDPLCD']==tone
    if typ=='TPL':
     assert float(f['CP_RXTPLFREQ' if side=='rx' else 'CP_TXTTPLFREQ'])==float(tone)
     assert f['CP_RXTPLCODE' if side=='rx' else 'CP_TXTPLCODE']==TPL_CODE[format(float(tone),'.1f')]
 for num,rule in rules.items():
  f=imported_check[rule['name']]
  if 'auto_scan' in rule:assert f['CP_UTOSCANEN']=='True' and f['CP_SCNROAMLISTIT']==scan_uuid[rule['scan_list']]
  else:assert f['CP_UTOSCANEN']=='False' and f['CP_SCNROAMLISTIT']==roam_uuid[rule['roaming_list']]
 # Configured list memberships must be valid and each roam TG must match.
 for lab,uid in scan_uuid.items():
  lst=next(x for x in records(ck['ScanItems']) if x.get('UUID')==uid)
  sitems=records(next(x for x in lst if x.get('Name')=='ScanListItems'))
  expected=next(x for x in req['scan_lists'] if x['name']==lab)
  assert len(sitems)==len(expected['members'])-1
  zone_item_to_alias={}
  for znode in records(ck['Zone']):
   for item in records(next(x for x in znode if x.get('Name')=='ZoneItems')):
    c_uuid=fdict(item)['ZP_PERSIT']
    ch=next((x for x in records(ck['ConventionalPersonality']) if x.get('UUID')==c_uuid),None)
    if ch is not None:zone_item_to_alias[item.get('UUID')]=fdict(ch)['CP_CNVPERSALIAS']
  actual_members=[zone_item_to_alias[fdict(x)['SP_CNVPERCOMP']] for x in sitems]
  expected_members=[x['name'] for x in expected['members'][1:]]
  assert actual_members==expected_members,('Scan member ordering mismatch',lab,actual_members,expected_members)
  assert not set(actual_members)&excluded
 for lab,uid in roam_uuid.items():
  lst=next(x for x in records(ck['RoamList']) if x.get('UUID')==uid)
  sitems=records(next(x for x in lst if x.get('Name')=='RoamListItems'))
  expected=next(x for x in req['roam_lists'] if x['name']==lab)
  assert len(sitems)==len(expected['members'])
  actual_members=[zone_item_to_alias[fdict(x)['SSP_CNVPERCOMP']] for x in sitems]
  expected_members=[x['name'] for x in expected['members']]
  assert actual_members==expected_members,('Roam member ordering mismatch',lab,actual_members,expected_members)
  assert not set(actual_members)&excluded
  for name_ch in actual_members:
   assert byname[name_ch]['tx_contact_id']==expected['required_talkgroup_id']
 result={'status':'TEST-ONLY. Archive round-trip + data/reference validation PASSED. NOT CPS2 GUI VALIDATED OR RADIO-TESTED.',
  'source_file':source.name,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
  'target_file':target.name,'target_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
  'generated_file':output.name,'generated_sha256':hashlib.sha256(output_bytes).hexdigest(),
  'model':header['dataModelVersion']['Version'],'original_channel_personalities_preserved':original_count,
  'new_source_channels_imported':len(src),'additional_personalities_for_repeated_zone_channels':imported_instances-len(src),'channel_personalities_total':counts['ConventionalPersonality'],
  'new_zones':new_zones,'source_zones':source_zones,'source_unassigned_channels':orphans,'cps2_records':counts,
  'zone_personality_uuid_one_to_one':True,'imported_zone_assignments':imported_zone_positions,
  'scan_lists':[{'name':s['name'],'members':len(s['members']),'contains_selected':True,'uuid':scan_uuid[s['name']]} for s in req['scan_lists']],
  'roam_lists':[{'name':s['name'],'members':len(s['members']),'talkgroup':s['required_talkgroup_id'],'uuid':roam_uuid[s['name']]} for s in req['roam_lists']],
  'new_contacts_created':new_contacts,'frequency_corrections':[{'channel_number':n,'alias':src[n-1]['channel_alias'],'original_tx_mhz':read_live_rdb(source)[0][n-1]['tx_mhz'],'corrected_tx_mhz':v,'reason':note} for n,(v,note) in corrections.items()],
  'channel_rules':req['channel_rules'],
  'excluded_from_lists_only':sorted(excluded),'preexisting_scan_memberships_removed':existing_scan_removals,
  'channels_preserved_verbatim':req['must_keep_channel_names'],
  'source_rx_group':source_rx_group,'rx_group_uuid':rx_group_uuid,'two_tone_source':two_tone,'two_tone_imported_systems_and_contacts':new_qcii,
  'two_tone_existing_motorola_change':staged_qcii,
  'two_tone_verified_source_to_archive_rows':len(verified_tones),
  'two_tone_status':f'Dynamically imported {len(new_qcii)} source QCII systems and linked contacts. Motorola CPS GUI untested.',
  'warnings':['Motorola CPS2 application validation is required before programming.',
              'Analog CTCSS/DCS tones and imported-channel admit criteria decoded/applied.',
              'RX-only decoded from CS711 channel byte 9; verify in CPS.',
              'Existing radio personalities and zones preserved; optional existing roaming lists may be remapped by profile.',
              'Verify frequency, scan, roaming, power, slot, signaling and legal TX permissions.',
              'Two-tone service/alert/recording flags are not mapped; source raw fields retained in audit.',
              'Generated reports may include sensitive radio configuration. Do not publish without review.']}
 # Full zone/position matrix, including repeat copies.
 # Failure to verify any zone position aborts the build.
 zone_report=[]
 check_alias_by_uuid={p.get('UUID'):fdict(p) for p in records(ck['ConventionalPersonality'])}
 for z in new_zones:
  zr=next(x for x in records(ck['Zone']) if x.get('UUID')==z['uuid'])
  for pos,zi in enumerate(records(next(x for x in zr if x.get('Name')=='ZoneItems')),1):
   source_index,expected_uid=expected_zone_assignments[z['uuid']][pos-1]
   actual_uid=fdict(zi)['ZP_PERSIT']
   source_rec=src[source_index-1]
   actual_f=check_alias_by_uuid[actual_uid]
   assert actual_uid==expected_uid
   assert actual_f['CP_CNVPERSALIAS']==source_rec['channel_alias']
   assert abs(float(actual_f['CP_RXFREQ'])-source_rec['rx_mhz'])<1e-8
   assert abs(float(actual_f['CP_TXFREQ'])-source_rec['tx_mhz'])<1e-8
   zone_report.append({'zone':z['name'],'position':pos,'cs_source_number':source_index,
     'cs_channel_name':source_rec['channel_alias'],'motorola_channel_name':actual_f['CP_CNVPERSALIAS'],
     'motorola_personality_uuid':actual_uid,'mode':source_rec['mode'],'rx_mhz':source_rec['rx_mhz'],
     'tx_mhz':source_rec['tx_mhz'],'tx_talkgroup':source_rec['tx_contact_id']})
 assert len(zone_report)==imported_zone_positions
 assert len({x['motorola_personality_uuid'] for x in zone_report})==len(zone_report)
 for regression in req['zone_regressions']:
  found=next(x for x in zone_report if x['zone']==regression['zone'] and x['position']==regression['position'])
  assert found['motorola_channel_name']==regression['channel'],regression
 result['zone_assignment_qa']={'result':'PASS',
   'all_positions_checked':len(zone_report),'all_personality_uuids_unique':True,
   'specific_profile_regressions':req['zone_regressions']}
 output.write_bytes(output_bytes)
 tonecsv=output.with_suffix('.2tone-verified.csv')
 with tonecsv.open('w',newline='',encoding='utf-8-sig') as f:
  dw=csv.DictWriter(f,fieldnames=list(verified_tones[0]));dw.writeheader();dw.writerows(verified_tones)
 # Keep source two-tone evidence in a separate, human-readable file so
 # the user can compare it directly with CS711 CPS without the XLSX exports.
 toneaudit=output.with_suffix('.2tone-source-audit.json')
 toneaudit.write_text(json.dumps({'source_rdb':source.name,'source_two_tone':two_tone,
   'motorola_existing_system_change':staged_qcii,
   'imported_qcii_systems_and_contacts':new_qcii,
   'important':'Each QCII definition comes from the source RDB two-tone table. Only Long Tone uses the documented placeholder A/B frequencies; C is source-derived. Startup message remains unmapped.'},indent=2)+'\n',encoding='utf-8')
 zonecsv=output.with_suffix('.zones-verified.csv')
 with zonecsv.open('w',newline='',encoding='utf-8') as f:
  dw=csv.DictWriter(f,fieldnames=list(zone_report[0]));dw.writeheader();dw.writerows(zone_report)
 audit=output.with_suffix('.qa.json');audit.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 csvp=output.with_suffix('.channels.csv')
 with csvp.open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=added[0].keys());w.writeheader();w.writerows(added)
 print('CANDIDATE',output,'BYTES',len(output_bytes),'SHA256',result['generated_sha256'],flush=True)
 print('COUNTS',counts, 'IMPORT',len(src),'ORIGINAL CHANNELS PRESERVED',original_count,flush=True)
 print('SCAN',[(s['name'],len(s['members'])) for s in req['scan_lists']],'ROAM',[(s['name'],len(s['members']),s['required_talkgroup_id']) for s in req['roam_lists']],flush=True)
 print('QA_REPORT',audit, 'CHANNELS_CSV',csvp, 'ZONES_CSV',zonecsv, '2TONE_VERIFIED_CSV',tonecsv, '2TONE_AUDIT',toneaudit,flush=True)
 print('RESULT: ARCHIVE DECODE/INTEGRITY + INTERNAL REFERENTIAL QA PASS. CS711 2TONE DEFS DYNAMICALLY IMPORTED:',len(new_qcii),'CPS APPLICATION TEST STILL REQUIRED.',flush=True)

def inspect_source(source, output, overwrite=False):
    """Create a source-only inspection file; no Motorola template required.

    The resulting JSON contains actual radio names, frequencies and contacts.
    Treat it as PRIVATE, just like the source .rdb.
    """
    if output.resolve() == source.resolve():
        raise ValueError('Inspection output must not overwrite the source')
    if output.exists() and not overwrite:
        raise ValueError('Inspection output already exists; use --force to overwrite')
    channels, contacts, zones, rx_group, two_tone = read_live_rdb(source)
    result = {
        'warning': 'PRIVATE CONFIGURATION DATA: do not upload this inventory publicly',
        'source_name': source.name,
        'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'channels': channels,
        'digital_contacts': contacts,
        'zones': zones,
        'rx_group': rx_group,
        'two_tone': two_tone,
        'scan_list_indices_observed': sorted({c['list_index'] for c in channels
                                              if c['list_index'] not in (0, 65535)
                                              and not c['auto_roam_candidate']}),
        'roam_talkgroups_observed': sorted({c['tx_contact_id'] for c in channels
                                           if c['auto_roam_candidate']
                                           and c['tx_contact_id'] is not None}),
    }
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    print('Source inventory:', output)
    print('Channels:', len(channels), 'Zones:', len(zones),
          '2-tone decode definitions:', len(two_tone['decode_definitions']))
    print('PRIVATE: The inventory contains real radio programming. Do not publish.')


if __name__=='__main__':
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('source', type=Path, help='Your own CS711 .rdb input file')
    ap.add_argument('target', type=Path, nargs='?',
                    help='Your own Motorola CPS2 .xctb starting codeplug (not needed for --inspect-source)')
    ap.add_argument('-o', '--output', type=Path, required=True,
                    help='New TEST-ONLY XCTB or source inventory JSON')
    ap.add_argument('--inspect-source', action='store_true',
                    help='Only decode CS711 source to PRIVATE inventory JSON (no target needed)')
    ap.add_argument('--profile', type=Path,
                    help='Optional PRIVATE per-radio scan/roam/frequency rules in JSON')
    ap.add_argument('--force', action='store_true',
                    help='Overwrite generated outputs noninteractively, never original inputs')
    ap.add_argument('--version', action='version', version='CS711-to-R7 experimental ' + __version__)
    args = ap.parse_args()
    if args.inspect_source:
        if args.target is not None:
            ap.error('Do not provide a Motorola target with --inspect-source')
        if args.profile is not None:
            ap.error('--profile is only for XCTB building')
        inspect_source(args.source, args.output, args.force)
    else:
        if args.target is None:
            ap.error('Motorola target XCTB is required unless --inspect-source is used')
        build(args.source, args.target, args.output, args.force, load_profile(args.profile))
