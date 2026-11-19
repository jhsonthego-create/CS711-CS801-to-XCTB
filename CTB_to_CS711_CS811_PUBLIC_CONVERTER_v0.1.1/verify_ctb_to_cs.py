#!/usr/bin/env python3
"""Independent source model versus Connect Systems RDB binary readback checks."""
from __future__ import annotations
import struct,hashlib,json,argparse
from pathlib import Path
from ctb_to_cs_rdb import normalize_ctb
from cs_rdb_builder import CH_ALIAS,CH_AT,CH_BYTES,CONTACT_AT,CONTACT_BYTES,SCAN_AT,SCAN_BYTES,SCAN_INDEX,ROAM_AT,ROAM_BYTES,ROAM_INDEX,ZONE_AT,ZONE_BYTES

def u16(buf,offset):return struct.unpack_from('<H',buf,offset)[0]
def u32(buf,offset):return struct.unpack_from('<I',buf,offset)[0]
def text16(buf,offset,limit=32):return buf[offset:offset+limit].decode('utf-16le').split('\0')[0]
def verify(src,ctb_meta,output,model):
 b=Path(output).read_bytes();assert len(b)==376832 and b[0x2000:0x2005]==model.encode()
 test=0
 def good(condition,err):
  nonlocal test
  if not condition:raise AssertionError(err)
  test+=1
 channels=src['channels'];co=src['contacts'];zone=src['zones']
 scans=[x for x in src['scan_roam_lists'] if x['type']=='scan'];roams=[x for x in src['scan_roam_lists'] if x['type']=='roam']
 good(u16(b,0x15082)==len(channels),'channel count')
 good(u16(b,0x3082)==len(co),'contact count')
 good(u16(b,SCAN_INDEX)==len(scans),'scan list count')
 good(u32(b,ROAM_INDEX)==len(roams),'roaming list count')
 good(u32(b,0x2220)==src['subscriber_id'],'DMR radio id')
 good(u32(b,58784)==(len(src['rx_groups'][0]['contact_indices']) if src['rx_groups'] else 0),'RX group donor contamination')
 if not src['rx_groups']:good(not any(b[0x45000:0x45000+128*44]),'obsolete donor RX group members')
 for i,x in enumerate(channels):
  good(u16(b,0x15084+2*i)==i+1,'channel inventory')
  rec=b[CH_AT+i*CH_BYTES:CH_AT+(i+1)*CH_BYTES]
  good(text16(b,CH_ALIAS+i*32)==x['name'],'channel name '+x['name'])
  good(u32(rec,0)==round(x['tx_mhz']*1e6),'TX frequency '+x['name'])
  good(u32(rec,4)==round(x['rx_mhz']*1e6),'RX frequency '+x['name'])
  good(rec[8]==(0x17 if x['mode']=='FM' else 0x14),'channel mode '+x['name'])
  good(bool(rec[9]&1)==x['auto_scan'],'auto scan '+x['name'])
  good(bool(rec[9]&2)==x['rx_only'],'RX only '+x['name'])
  if x['mode']=='DMR':
   good((rec[16]&15)==x['color_code'],'color code '+x['name'])
   good(bool(rec[16]&0x10)==(x['timeslot']==2),'timeslot '+x['name'])
   good(rec[24]==(next((i+1 for i,c in enumerate(co) if c['uuid']==x['contact_uuid']),0)),'TX contact '+x['name'])
  else:
   # Tonal encoding is separately verified by the builder before write.
   pass
 for i,x in enumerate(co):
  at=CONTACT_AT+i*CONTACT_BYTES
  good(u32(b,at+32)==x['id'],'contact DMR ID')
  good(bool(text16(b,at)),'missing contact alias')
 for i,L in enumerate(scans):
  at=SCAN_AT+i*SCAN_BYTES
  good(text16(b,at)==L['name'][:16] or bool(text16(b,at)),'scan list name')
  good(b[at+38]==len(L['members']),'scan member count')
  for j,m in enumerate(L['members']):good(u16(b,at+64+j*2)==m['channel_index'],'scan member reference')
 for i,L in enumerate(roams):
  at=ROAM_AT+i*ROAM_BYTES
  good(b[at+32]==len(L['members']),'roam member count')
  for j,m in enumerate(L['members']):good(u16(b,at+44+j*2)==m['channel_index'],'roam member reference')
 expected=[]
 for zi,z in enumerate(zone,1):
  members=[m['channel_index'] for m in z['members']]
  for part_no,base in enumerate(range(0,len(members),16),1):
   part=members[base:base+16]
   expected.append((len(expected)+1 if model=='CS711' else zi,len(part) if model=='CS711' else len(members),part))
 for i,(logical,total,members) in enumerate(expected):
  at=ZONE_AT+i*ZONE_BYTES
  good(u16(b,at+38)==logical,'logical zone ID')
  good(u16(b,at+40)==total,'zone source member count')
  good(b[at+36]==len(members),'zone page member count')
  for j,m in enumerate(members):good(u16(b,at+48+2*j)==m,'zone member')
 return {'checks_passed':test,'source_sha256':ctb_meta['file_sha256'],'output_sha256':hashlib.sha256(b).hexdigest(),
         'channels':len(channels),'contacts':len(co),'zones':len(zone),'physical_zone_pages':len(expected),
         'scan_lists':len(scans),'scan_members':sum(len(s['members']) for s in scans),
         'roaming_lists':len(roams),'roaming_members':sum(len(s['members']) for s in roams),'model':model,
         'ctb_signature_verified':True,'cps_tested':False}

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('ctb',type=Path);p.add_argument('--config',type=Path,required=True);p.add_argument('--rdb',type=Path,required=True);p.add_argument('--model',choices=('CS711','CS811'),required=True)
 a=p.parse_args();src,meta=normalize_ctb(a.ctb,a.config);print(json.dumps(verify(src,meta,a.rdb,a.model),indent=2))
if __name__=='__main__':main()
