#!/usr/bin/env python3
"""Public CS711 RDB forensic exporter: decoded CSV, XML, text and lossless raw bytes.
Only currently decoded fields have semantic names. No user codeplugs are bundled.
"""
import argparse
from pathlib import Path
import base64, csv, hashlib, json, re, shutil, textwrap, xml.etree.ElementTree as ET, zipfile
from cs711_to_xctb import read_live_rdb

def main():
 parser = argparse.ArgumentParser(description='Export supported CS711 RDB to XML, CSV, text and lossless ZIP')
 parser.add_argument('rdb', type=Path, help='Your CS711 .rdb codeplug')
 parser.add_argument('-o','--output', type=Path, help='Output directory (default: <rdb stem>_export)')
 parser.add_argument('--include-original', action='store_true', help='Also copy source .rdb into ZIP (otherwise raw bytes remain embedded in XML)')
 parser.add_argument('--force', action='store_true', help='Allow writing to a nonempty output directory')
 args = parser.parse_args()
 if not args.rdb.is_file(): parser.error('RDB file not found')
 SOURCE = args.rdb.resolve()
 OUT = args.output.resolve() if args.output else SOURCE.with_name(SOURCE.stem + '_export')
 if OUT.exists() and any(OUT.iterdir()) and not args.force:
  raise SystemExit(f'Output directory not empty: {OUT}. Use --force to overwrite.')
 OUT.mkdir(parents=True, exist_ok=True)
 raw=SOURCE.read_bytes()
 channels, contacts, zones, rxgroup, two_tone = read_live_rdb(SOURCE)
 sha=hashlib.sha256(raw).hexdigest()

 # Source records only: not Motorola defaults or manually asserted scan/roam membership.
 def csv_write(filename, rows, fields=None):
  rows=list(rows)
  if fields is None:
   fields=list(dict.fromkeys(k for row in rows for k in row))
  p=OUT/filename
  with p.open('w',encoding='utf-8-sig',newline='') as fp:
   w=csv.DictWriter(fp,fieldnames=fields,extrasaction='ignore'); w.writeheader()
   for row in rows:
    w.writerow({k: (json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v) for k,v in row.items()})
  return p

 rawchannel=[]
 for c in channels:
  n=c['channel_number']; start=120192+32*(n-1); alias_start=88192+32*(n-1)
  rawchannel.append({**c,'channel_record_offset_dec':start,'channel_record_offset_hex':hex(start),'channel_record_32_bytes_hex':raw[start:start+32].hex(' '),'alias_record_offset_dec':alias_start,'alias_record_32_bytes_hex':raw[alias_start:alias_start+32].hex(' ')})
 csv_write('CS711_SOURCE_CHANNELS.csv',rawchannel)
 rawcontact=[]
 for idx,c in contacts.items():
  start=14464+44*(idx-1)
  rawcontact.append({'source_contact_index':idx,**c,'rdb_offset_dec':start,'source_raw_44_bytes_hex':raw[start:start+44].hex(' ')})
 csv_write('CS711_SOURCE_CONTACTS.csv',rawcontact)

 zone_rows=[]; zone_summaries=[]
 for zidx,z in enumerate(zones,1):
  at=152192+80*(zidx-1)
  zone_summaries.append({'source_zone_index':zidx,'name':z['name'],'channel_count':len(z['ids']),'rdb_offset_dec':at,'source_raw_80_bytes_hex':raw[at:at+80].hex(' ')})
  for p,cidx in enumerate(z['ids'],1):
   c=channels[cidx-1]
   zone_rows.append({'source_zone_index':zidx,'zone_name':z['name'],'position':p,'channel_number':cidx,'channel_alias':c['channel_alias'],'mode':c['mode'],'rx_mhz':c['rx_mhz'],'tx_mhz':c['tx_mhz']})
 csv_write('CS711_SOURCE_ZONES.csv',zone_rows)
 csv_write('CS711_SOURCE_ZONE_RECORDS.csv',zone_summaries)

 rxgroup_rows=[]
 for p,ci in enumerate(rxgroup['contact_indexes'],1):
  rxgroup_rows.append({'rx_group_name':rxgroup['name'],'position':p,'contact_index':ci,**contacts[ci]})
 csv_write('CS711_SOURCE_RX_GROUP_MEMBERS.csv',rxgroup_rows)

 tone_rows=[]
 for d in two_tone['decode_definitions']:
  r=dict(d)
  r['cs711_decode_type']='Sel Call'
  r['source_call_format_cps']='Two Tone' if d['source_call_format']=='Two Tone' else 'Long Tone'
  r['source_frequency_1_hz']=d['source_tone_1_hz']
  r['source_frequency_2_hz']=d['source_tone_2_hz']
  r['source_frequency_2_active']=d['source_call_format']=='Two Tone'
  for key in ('tone_a_hz','tone_b_hz','tone_c_hz','dummy_ab','format'):
   r.pop(key,None) # Motorola conversions are not part of SOURCE export
  tone_rows.append(r)
 csv_write('CS711_SOURCE_2TONE_DECODE_DEFS.csv',tone_rows)

 # Every nonzero 256-byte physical block, untouched; no claim of decoding unknown records.
 block_rows=[]
 for start in range(0,len(raw),256):
  part=raw[start:start+256]
  block_rows.append({'offset_dec':start,'offset_hex':f'0x{start:06X}','bytes':len(part),'nonzero_bytes':len(part)-part.count(0),'hex':part.hex()})
 csv_write('CS711_ALL_RAW_256_BYTE_BLOCKS.csv',block_rows)

 # Extract merely candidates: false positives possible; do not imply a CPS field mapping.
 strings=[]
 for encoding in ['ascii','utf-16le']:
  if encoding=='ascii':
   for m in re.finditer(rb'[\x20-\x7e]{4,}',raw):
    strings.append({'encoding':'ASCII candidate','offset_dec':m.start(),'offset_hex':hex(m.start()),'text':m.group().decode('ascii')})
  else:
   # UTF-16LE string sequences starting on either alignment.
   for parity in [0,1]:
    pattern=rb'(?:[\x20-\x7e]\x00){4,}'
    for m in re.finditer(pattern,raw[parity:]):
     at=parity+m.start()
     strings.append({'encoding':'UTF-16LE candidate','offset_dec':at,'offset_hex':hex(at),'text':m.group().decode('utf-16le')})
 strings.sort(key=lambda a:(a['offset_dec'],a['encoding']))
 csv_write('CS711_CANDIDATE_TEXT_STRINGS.csv',strings)

 # Detailed XML readable element-per-field and byte-for-byte original embedded in Base64.
 root=ET.Element('CS711SourceCodeplugExport',{'exportType':'analysis-not-CS711-CPS-importable','sourceFormat':'CS711-RDB','decoder':'known record fields plus lossless raw binary'})
 meta=ET.SubElement(root,'SourceFile',{'filename':SOURCE.name,'lengthBytes':str(len(raw)),'sha256':sha})
 ET.SubElement(meta,'Identity',{'radioModelMarker':raw[8192:8197].decode('ascii', errors='replace'),'markerOffset':'8192'})
 rawaliases=ET.SubElement(root,'RadioIdentityAndStartup')
 ET.SubElement(rawaliases,'RadioAlias',{'sourceOffset':'8704'}).text=two_tone['radio_alias']
 ET.SubElement(rawaliases,'PowerOnMessage',{'sourceOffset':'8744','motorolaMapping':'unmapped'}).text=two_tone['power_on_message_unmapped']

 def attrs_and_content(parent,name, data, *, raw_hex_key=None):
  nd=ET.SubElement(parent,name)
  for k,v in data.items():
   if v is None: ET.SubElement(nd,k,{'isNull':'true'}); continue
   if isinstance(v,(dict,list)): ET.SubElement(nd,k).text=json.dumps(v,ensure_ascii=False)
   else:ET.SubElement(nd,k).text=str(v)
  return nd

 nd=ET.SubElement(root,'Channels',{'count':str(len(channels))})
 for d in rawchannel: attrs_and_content(nd,'Channel',d)
 nd=ET.SubElement(root,'DigitalContacts',{'count':str(len(contacts))})
 for d in rawcontact:attrs_and_content(nd,'Contact',d)
 nd=ET.SubElement(root,'Zones',{'count':str(len(zones))})
 for zsummary,z in zip(zone_summaries,zones):
  zz=attrs_and_content(nd,'ZoneRecord',zsummary)
  mm=ET.SubElement(zz,'Members')
  for p,idx in enumerate(z['ids'],1):
   ET.SubElement(mm,'Member',{'position':str(p),'channelSourceIndex':str(idx),'channelName':channels[idx-1]['channel_alias']})
 nd=ET.SubElement(root,'ReceiveGroups',{'count':'1','sourceOffset':'58784'})
 g=ET.SubElement(nd,'ReceiveGroup',{'name':rxgroup['name']})
 for row in rxgroup_rows: attrs_and_content(g,'Member',row)
 ET.SubElement(g,'RawSourceBytes',{'offset':'58784','encoding':'hex'}).text=raw[58784:58784+128].hex()
 nd=ET.SubElement(root,'TwoToneAnalogServices',{'sourceDecoderCount':str(len(tone_rows))})
 ET.SubElement(nd,'SystemRawSourceBytes',{'offsetDec':'254976','sizeBytes':'256','encoding':'hex','notFullyDecoded':'true'}).text=raw[254976:255232].hex()
 ET.SubElement(nd,'GeneralSettingsRawSourceBytes',{'offsetDec':'255232','sizeBytes':'32','encoding':'hex','notFullyDecoded':'true'}).text=raw[255232:255264].hex()
 for d in tone_rows:attrs_and_content(nd,'DecodeDefinition',d)
 ET.SubElement(nd,'Notes').text='Only decoded source fields are represented as named fields. Unmapped 2Tone System/Service settings remain present as raw bytes and in the full RDB payload. No Motorola placeholder tones were written to this source export.'
 # Lossless file, not a reconstruction; gives complete source even for data with unknown schema.
 ET.SubElement(root,'EntireOriginalRDB',{'encoding':'base64','byteLength':str(len(raw)),'sha256':sha,'purpose':'Lossless byte-for-byte source; includes all fields, parsed or unknown'}).text='\n'+'\n'.join(textwrap.wrap(base64.b64encode(raw).decode('ascii'),96))+'\n'
 ET.indent(root,space='  ')
 xmlpath=OUT/'CS711_COMPLETE_SOURCE_EXPORT.xml'
 ET.ElementTree(root).write(xmlpath,encoding='utf-8',xml_declaration=True)

 # Human-readable text of every parsed field, explicitly source-only.
 with (OUT/'CS711_ALL_DECODED_SOURCE.txt').open('w',encoding='utf-8') as fp:
  fp.write('CS711 SOURCE CODEPLUG — ALL CURRENTLY IDENTIFIED FIELDS\n')
  fp.write(f'Original: {SOURCE.name}\nSHA256: {sha}\nFile size: {len(raw)} bytes\n')
  fp.write('Unknown records are NOT represented as known settings. For complete bytes, consult original .rdb or the XML Base64 field.\n')
  for heading,obj in [('IDENTITY / STARTUP',{'Radio Alias':two_tone['radio_alias'],'Power On Message':two_tone['power_on_message_unmapped']}),('ANALOG 2TONE SYSTEM RAW',{'System raw hex':raw[254976:255232].hex(),'General raw hex':raw[255232:255264].hex()}),('2TONE DECODE DEFINITIONS',tone_rows),('DIGITAL CONTACTS',rawcontact),('CHANNELS',rawchannel),('ZONES',zone_rows),('RX GROUP MEMBERS',rxgroup_rows),('ALL DETECTED STRING CANDIDATES',strings)]:
   fp.write('\n'+'='*70+'\n'+heading+'\n'+'='*70+'\n')
   if isinstance(obj,list):
    for item in obj:fp.write(json.dumps(item,ensure_ascii=False)+'\n')
   else:fp.write(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')

 with (OUT/'CS711_COMPLETE_RDB_HEXDUMP.txt').open('w',encoding='ascii') as fp:
  for start in range(0,len(raw),16):
   chunk=raw[start:start+16]
   ascii_preview=''.join(chr(c) if 32<=c<=126 else '.' for c in chunk)
   fp.write(f'{start:08X}  '+chunk.hex(' ').ljust(47)+f'  |{ascii_preview}|\n')
 if args.include_original: shutil.copy2(SOURCE,OUT/SOURCE.name)
 readme=f'''CS711 — COMPLETE SOURCE EXPORT
 ================================
 Original: {SOURCE.name}
 Original file SHA256: {sha}
 Original byte count: {len(raw)}

 OPEN THIS FIRST:
 - CS711_COMPLETE_SOURCE_EXPORT.xml    Source-only decoded data plus WHOLE ORIGINAL RDB in Base64.
 - CS711_ALL_DECODED_SOURCE.txt         Plain-text readable catalog of decoded settings.
 - CS711_SOURCE_2TONE_DECODE_DEFS.csv   ALL {len(tone_rows)} source 2Tone Decode Defs.
 - CS711_SOURCE_CHANNELS.csv            ALL {len(channels)} decoded channels and original 32-byte records.
 - CS711_SOURCE_CONTACTS.csv            ALL {len(contacts)} digital contacts.
 - CS711_SOURCE_ZONES.csv               ALL {len(zone_rows)} source zone channel assignments.
 - CS711_SOURCE_ZONE_RECORDS.csv        ALL {len(zones)} zone records including raw bytes.
 - CS711_SOURCE_RX_GROUP_MEMBERS.csv    All {len(rxgroup_rows)} RX group members.
 - CS711_CANDIDATE_TEXT_STRINGS.csv     Candidate ASCII/UTF16 strings; includes possible false positives.
 - CS711_ALL_RAW_256_BYTE_BLOCKS.csv    Every byte of the original file, split into indexed blocks.
 - CS711_COMPLETE_RDB_HEXDUMP.txt       A readable hexdump of EVERY byte.
 - Original RDB is included only when --include-original is specified.

 TWO-TONE:
 All source decode definitions are exported from the input RDB dynamically.
 This is a SOURCE export: dummy Motorola conversion tones 296.5 and 1930.2
 are NOT source data and are NOT inserted as decoded RDB fields.

 CRITICAL DISTINCTION:
 This XML is a comprehensive ANALYSIS EXPORT, not a vendor-native CS711 XML
 file and cannot be imported by the CS711 CPS as-is.
 'Export everything' includes 100% of original source bytes, so fields whose
 binary encoding is not yet known are INCLUDED losslessly but are not falsely
 represented as decoded named settings.
 '''
 (OUT/'README-READ-FIRST.txt').write_text(readme,encoding='utf-8')

 # Validation: reconstruct entire RDB payload from XML and compare hash and bytes.
 parsed=ET.parse(xmlpath).getroot()
 recovered=base64.b64decode(''.join(parsed.find('EntireOriginalRDB').text.split()))
 assert recovered==raw,(len(recovered),len(raw))
 assert len(tone_rows)==len(two_tone['decode_definitions'])
 assert all(t['source_call_format'] in ('Two Tone','Long Tone') for t in tone_rows)
 for c in rawchannel:assert bytes.fromhex(c['channel_record_32_bytes_hex'])==raw[c['channel_record_offset_dec']:c['channel_record_offset_dec']+32]

 zipout=OUT.parent / (OUT.name + '.zip')
 with zipfile.ZipFile(zipout,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
  for p in sorted(OUT.iterdir()):
   if p.is_file():z.write(p,arcname=p.name)
 print(json.dumps({'export_zip':str(zipout),'export_xml':str(xmlpath),'plain_text':str(OUT/'CS711_ALL_DECODED_SOURCE.txt'),'two_tone_csv':str(OUT/'CS711_SOURCE_2TONE_DECODE_DEFS.csv'),'counts':{'source_channels':len(channels),'contacts':len(contacts),'zones':len(zones),'zone_memberships':len(zone_rows),'two_tone_definitions':len(tone_rows),'candidate_strings':len(strings),'source_bytes':len(raw)},'checks':{'source_byte_for_byte_xml_roundtrip':'PASSED','2tone_source_count':'PASSED'},'size_zip_bytes':zipout.stat().st_size},indent=2))

if __name__ == '__main__':
 main()
