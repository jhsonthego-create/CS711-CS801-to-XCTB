#!/usr/bin/env python3
"""Motorola CPS1 CTB (MATRIX/GEMSTONE) -> Connect Systems CS711/CS811 RDB.

Experimental, no radio programming: destination CPS open/save/reopen required.
Source CTB and donor RDB are never modified. The exact raw Motorola CTB
payload is verified with its embedded RSA/SHA1 signature before conversion.
The destination is rebuilt using known binary record layouts, not Motorola XML
fields. No CPS DLL, user codeplug, AES material or signing certificate embedded.
"""
from __future__ import annotations
import argparse,base64,configparser,gzip,hashlib,html,json,re,sys
from pathlib import Path
from collections import Counter
from lxml import etree
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cs_rdb_builder import patch


def require(cond,msg):
    if not cond:raise ValueError(msg)


def matrix_charstream_to_bytes(text):
    # Motorola CPS1 MATRIX <RADIO> serializes binary ciphertext as Windows-1252
    # characters, escaped with XML numeric references for low controls. Python's
    # html.unescape would corrupt &#x0;..&#x1f; by HTML5 replacement rules.
    text=re.sub(r'&#(?:x([0-9A-Fa-f]+)|([0-9]+));',
                lambda m:chr(int(m.group(1),16) if m.group(1) else int(m.group(2))),text)
    text=html.unescape(text)
    buf=bytearray()
    for char in text:
        try:buf.extend(char.encode('cp1252'))
        except UnicodeEncodeError:
            require(ord(char)<256, 'MATRIX ciphertext contains unexpected Unicode character U+%04X'%ord(char))
            buf.append(ord(char))
    return bytes(buf)


def load_aes_config(configfile):
    cfg=configparser.ConfigParser(interpolation=None);require(cfg.read(configfile) and cfg.has_section('codeplug'),'Missing [codeplug] config')
    key=base64.b64decode(cfg['codeplug']['key'],validate=True)
    iv=base64.b64decode(cfg['codeplug']['iv'],validate=True)
    require(len(key)==32 and len(iv)==16, 'CTB key must be 32 bytes, IV must be 16 bytes')
    return key,iv


def decode_ctb(path,configfile):
    raw=Path(path).read_bytes()
    # Deliberately parse envelope without parsing the invalid numeric control
    # references in a MATRIX ciphertext as XML.
    typ=re.match(rb'<ARCHIVE\s+TYPE="(GEMSTONE|MATRIX|PARADISE_LIGHT)"',raw)
    require(typ is not None,'Unsupported CPS1 CTB archive type')
    kind=typ.group(1).decode('ascii')
    m=re.search(rb'<RADIO\s+VERSION="1"[^>]*>(.*?)</RADIO>',raw,re.S)
    require(m is not None, 'CTB missing RADIO payload')
    if kind=='MATRIX':
        encrypted=matrix_charstream_to_bytes(m.group(1).decode('utf-8'))
    else:
        encrypted=base64.b64decode(m.group(1).strip(),validate=True)
    require(encrypted and len(encrypted)%16==0,'Invalid AES ciphertext size')
    key,iv=load_aes_config(configfile)
    ctx=Cipher(algorithms.AES(key),modes.CBC(iv)).decryptor()
    padded=ctx.update(encrypted)+ctx.finalize()
    unpad=PKCS7(128).unpadder();compressed=unpad.update(padded)+unpad.finalize()
    require(compressed.startswith(b'\x1f\x8b\x08'), 'CTB decrypted data is not GZIP')
    signed=gzip.decompress(compressed)
    require(len(signed)<32*1024*1024 and signed.startswith(b'\xef\xbb\xbf<LTD_CODEPLUG'), 'CTB uncompressed payload invalid')
    sigstart=signed.rfind(b'<SIGNATURE>')
    require(sigstart>0,'CTB signature missing')
    xml=signed[3:sigstart]
    signature=etree.fromstring(signed[sigstart:],etree.XMLParser(resolve_entities=False,no_network=True))
    require(signature.findtext('VERSION')=='1.0','Unsupported signature version')
    n=int.from_bytes(base64.b64decode(signature.findtext('RSAKeyValue/Modulus')),'big')
    e=int.from_bytes(base64.b64decode(signature.findtext('RSAKeyValue/Exponent')),'big')
    rsa=RSAPublicNumbers(e,n).public_key()
    rsa.verify(bytes.fromhex(signature.findtext('DIGEST')),xml.decode('utf-8').encode('utf-16-le'),asym_padding.PKCS1v15(),hashes.SHA1())
    # The original signature verifies against the untouched data. Known old
    # CPS1 illegal XML character references must be repaired ONLY for parsing.
    parse_xml=re.sub(rb'&#xFFFF;',b'&#xFFFD;',xml,flags=re.I)
    root=etree.fromstring(parse_xml,etree.XMLParser(huge_tree=True,no_network=True,resolve_entities=False))
    require(root.tag=='LTD_CODEPLUG','Not a Motorola LTD_CODEPLUG')
    metadata={'type':kind,'ctb_xml_version':root.get('VERSION'),'file_sha256':hashlib.sha256(raw).hexdigest(),
              'verified_original_motorola_signature':True,'xml_sha256':hashlib.sha256(xml).hexdigest()}
    return root,metadata


def child(node,tag,default=None):
    x=node.find(tag)
    if x is None or x.text is None:return default
    return x.text


def refid(node,tag,target_type):
    x=node.find(tag)
    if x is None or x.get('TypeID')!=target_type:return None
    s=(x.text or '').strip()
    if not s.isdigit():return None
    return int(s)


def aliased(name,order,used):
    s=' '.join(str(name or '').split()).strip() or ('Item'+str(order))
    s=s[:16]
    if s.casefold() in used:
        suffix='~'+str(order)
        s=s[:16-len(suffix)]+suffix
    if s.casefold() in used:raise ValueError('Channel name collisions after truncation')
    used.add(s.casefold());return s


def to_bool(s):return str(s or '').strip().lower() in ('1','true','yes','enabled')


def normalize_ctb(source_path,config_path):
    root,meta=decode_ctb(source_path,config_path)
    grp=root.find('.//CNV_PER_CMP_TYPE_GRP')
    require(grp is not None and len(grp)>0,'No conventional personalities in CTB')
    channel_map={};channels=[];used=set();source_channel_ids=[]
    for ix,n in enumerate(grp,1):
        typ=child(n,'CP_PERSTYPE','')
        require(typ in ('ANLGCONV','DGTLCONV6PT25'),f'Unsupported CPS1 personality {typ!r} at {ix}')
        source_id=int(n.get('ListID','-1'))
        require(source_id not in channel_map,f'Duplicate Motorola conventional personality ListID {source_id}')
        source_channel_ids.append(source_id)
        original=child(n,'CP_CNVPERSALIAS',f'Channel {ix}')
        bw=child(n,'CP_CHNLBWDTH','')
        rxkind=child(n,'CP_XSQCHTY','CSQ');txkind=child(n,'CP_TXSQCHTY','CSQ')
        require(rxkind in ('CSQ','TPL','DPL') and txkind in ('CSQ','TPL','DPL'),f'Unsupported analog squelch setting {original}')
        channel={
         'index':ix,'uuid':f'personality-{source_id}','source_name':original,'name':aliased(original,ix,used),
         'mode':'FM' if typ=='ANLGCONV' else 'DMR','rx_mhz':float(child(n,'CP_RXFREQ')),
         'tx_mhz':float(child(n,'CP_TXFREQ')),'rx_only':to_bool(child(n,'CP_RXONLYEN')),
         'power':'Low' if child(n,'CP_TXPWR')=='LOWPWR' else 'Max',
         'timeout':int(child(n,'CP_TOT','0')),'bandwidth':25.0 if '25KHZ' in bw and '12PT5' not in bw else 12.5,
         'color_code':int(child(n,'CP_COLORCODE','0')),'timeslot':2 if child(n,'CP_SLTASSGMNT')=='SLOT2' else 1,
         'rx_tone_type':rxkind,'tx_tone_type':txkind,
         'rx_tone_value':child(n,'CP_RXTPLFREQ','') if rxkind=='TPL' else child(n,'CP_RXDPLCD','') if rxkind=='DPL' else '',
         'tx_tone_value':child(n,'CP_TXTTPLFREQ','') if txkind=='TPL' else child(n,'CP_TXTDPLCD','') if txkind=='DPL' else '',
         'rx_invert':to_bool(child(n,'CP_RXDPLINV')),'tx_invert':to_bool(child(n,'CP_TXDPLINV')),
         'contact_uuid':None,'rxgroup_uuid':None,'scan_roam_uuid':None,'auto_scan':to_bool(child(n,'CP_UTOSCANEN')),
         'vox':to_bool(child(n,'CP_VOXSTATE')),'original_personality_type':typ,
         '_ref_contact':refid(n,'CP_UKPPERS','DIGITAL_UCL_DLL_TYPE'),
         '_ref_rxgroup':refid(n,'CP_TGLISTIT','RX_TG_LIST_DLH_TYPE'),
         '_ref_scan':refid(n,'CP_SCNROAMLISTIT','SCAN_PER_DLH_TYPE'),
         '_ref_scan_alt':refid(n,'CP_SCANPERSLISTIT','SCAN_PER_DLH_TYPE'),
         '_ref_roam':refid(n,'CP_SCNROAMLISTIT','ST_SRCH_DLH_TYPE'),
        }
        require(0<channel['rx_mhz']<1000 and 0<channel['tx_mhz']<1000,'Invalid source frequency')
        channel_map[source_id]=channel;channels.append(channel)

    def group_items(tag,entry):
        n=root.find('.//'+tag)
        return list(n) if n is not None else []
    # Motorola list references are by ListLetID (not by file/XML position).
    contact_map={};contacts=[]
    for g in group_items('DIGITAL_UCL_DLH_TYPE_GRP',''):
        for node in g.findall('DIGITAL_UCL_DLL_TYPE'):
            num=int(node.get('ListLetID','-1'))
            require(num not in contact_map,'Duplicate CTB contact ListLetID')
            typecode=child(node,'DU_CALLTYPE','GRPCALL')
            require(typecode in ('GRPCALL','PRIVCALL','ALLCALL'),'Unknown DMR call type: '+typecode)
            co={'index':len(contacts)+1,'uuid':f'contact-{num}','name':child(node,'DU_CALLALIAS',f'Contact{num}'),
                'id':int(child(node,'DU_CALLLSTID','0')),
                'type':{'GRPCALL':'Group','PRIVCALL':'Private','ALLCALL':'All'}[typecode],'raw_type':typecode,
                'source_listlet_id':num}
            require(0<=co['id']<=16776415,'Invalid DMR contact ID')
            contacts.append(co);contact_map[num]=co
    grps=[];grp_map={}
    for node in group_items('RX_TG_LIST_DLH_TYPE_GRP',''):
        gid=int(node.get('ListID','-1'))
        require(gid not in grp_map,'Duplicate CTB RX group ListID')
        members=[]
        for mem in node.findall('RX_TG_LIST_DLL_TYPE'):
            rid=refid(mem,'RXTG_DGUCLCOMP','DIGITAL_UCL_DLL_TYPE')
            require(rid in contact_map, f'Unknown RX group contact reference {rid}')
            members.append(contact_map[rid]['index'])
        rec={'uuid':f'rxgroup-{gid}','name':child(node.find('RX_TG_LIST_DLH_TYPE'),'RXTG_RXTGLISTALIAS',f'RX Group{gid}'),
             'contact_indices':members,'source_list_id':gid}
        grp_map[gid]=rec
        # Empty CPS default groups have no practical RDB membership.
        if members:grps.append(rec)
    require(len(grps)<=1,'This RDB layout supports one nonempty RX group; source has '+str(len(grps)))

    zones=[]
    for node in group_items('ZN_PER_ASGN_DLH_TYPE_GRP',''):
        name=child(node.find('ZN_PER_ASGN_DLH_TYPE'),'ZP_ZONEALIAS',f'Zone{len(zones)+1}')
        members=[]
        for mem in node.findall('ZN_PER_ASGN_DLL_TYPE'):
            ref=refid(mem,'ZP_PERSIT','CNV_PER_CMP_TYPE')
            require(ref in channel_map, f'Unknown zone channel ID {ref} in {name!r}')
            c=channel_map[ref]
            members.append({'source_uuid':c['uuid'],'channel_index':c['index'],'channel_name':c['name']})
        if members:
            zones.append({'index':len(zones)+1,'name':name,'members':members})
    # Scan + roaming: skip empty CPS placeholder lists unless a personality
    # explicitly references them; otherwise preserve all members and IDs.
    lists=[];scan_map={};roam_map={}
    for kind,tag,container,header,alias,membertag,reffield,expected in [
      ('scan','SCAN_PER_DLH_TYPE_GRP','SCAN_PER_DLT_TYPE','SCAN_PER_DLH_TYPE','SP_SCANLISTALIAS','SCAN_PER_DLL_TYPE','SP_CNVPERCOMP','CNV_PER_CMP_TYPE'),
      ('roam','ST_SRCH_DLH_TYPE_GRP','ST_SRCH_DLT_TYPE','ST_SRCH_DLH_TYPE','SSP_SCANLISTALIAS','ST_SRCH_DLL_TYPE','SSP_CNVPERCOMP','CNV_PER_CMP_TYPE')]:
        known={}
        for node in group_items(tag,''):
            i=int(node.get('ListID','-1'))
            require(i not in known,'Duplicate Motorola '+kind+' ListID')
            name=child(node.find(header),alias,f'{kind}{i}')
            members=[]
            for mem in node.findall(membertag):
                uid=refid(mem,reffield,expected)
                require(uid in channel_map,f'Unknown {kind} channel ID {uid} in {name}')
                c=channel_map[uid]
                members.append({'source_uuid':c['uuid'],'channel_index':c['index'],'channel_name':c['name']})
            known[i]={'index':i,'uuid':f'{kind}-{i}','name':name,'type':kind,'members':members}
        for c in channels:
            uid=c['_ref_roam'] if kind=='roam' else (c['_ref_scan'] if c['_ref_scan'] is not None else c['_ref_scan_alt'])
            if uid is not None:require(uid in known,'Channel references nonexistent '+kind+' ListID '+str(uid))
        for i,li in known.items():
            referenced=any(c['_ref_roam']==i if kind=='roam' else c['_ref_scan']==i or c['_ref_scan_alt']==i for c in channels)
            if li['members'] or referenced:
                lists.append(li)
                (scan_map if kind=='scan' else roam_map)[i]=li
    for c in channels:
        # If both are configured, roaming is the selected higher priority list;
        # analog channels must never be assigned a DMR roaming list.
        if c['_ref_roam'] is not None:
            require(c['mode']=='DMR','Analog channel references a roaming list')
            c['scan_roam_uuid']=roam_map[c['_ref_roam']]['uuid']
        else:
            n=c['_ref_scan'] if c['_ref_scan'] is not None else c['_ref_scan_alt']
            if n is not None:c['scan_roam_uuid']=scan_map[n]['uuid']
        co=contact_map.get(c['_ref_contact'])
        if c['_ref_contact'] is not None:require(co is not None,'Unknown TX contact referenced from '+c['source_name'])
        if co:c['contact_uuid']=co['uuid'];c['tx_contact']=co
        else:c['tx_contact']=None
        gr=grp_map.get(c['_ref_rxgroup'])
        if c['_ref_rxgroup'] is not None:require(gr is not None,'Unknown RX group referenced from '+c['source_name'])
        if gr and gr['contact_indices']:c['rxgroup_uuid']=gr['uuid'];c['rx_group']=gr
        else:c['rx_group']=None
        for t in ('_ref_contact','_ref_rxgroup','_ref_scan','_ref_scan_alt','_ref_roam'):c.pop(t)
    identity=root.find('.//RC_SUBSCRIBERID')
    if identity is None:identity=root.find('.//RC_SUBSCRIBERID_CPS')
    require(identity is not None and identity.text is not None,'CTB radio DMR ID missing')
    rid=int(identity.text)
    require(1<=rid<=16776415,'Invalid CTB subscriber ID')
    out={'subscriber_id':rid,'source_file':Path(source_path).name,'source_sha256':meta['file_sha256'],
         'source_format':'Motorola CPS1 CTB '+meta['type'],'source_datamodel':meta['ctb_xml_version'],
         'channels':channels,'zones':zones,'contacts':contacts,'rx_groups':grps,'scan_roam_lists':lists}
    return out,meta


def convert(ctb,config,donor,model,output,alias='Imported CTB',strict_band=True,allow_donor_two_tone=False):
    # Fail closed: destination RDB donors may carry unrelated two-tone programming.
    # The binary two-tone layout has not been mapped sufficiently to clear it safely.
    if not allow_donor_two_tone:
        raise ValueError('REFUSED: destination RDB donor two-tone definitions would be retained. This converter cannot yet prove they are empty or clear them safely. No output written. For a deliberate private donor-preserving experiment only, use --allow-donor-two-tone; never use that option for public conversion.')
    source,metadata=normalize_ctb(ctb,config)
    fqs=[(c['rx_mhz'],c['tx_mhz']) for c in source['channels']]
    # Both proven donor binaries in this distribution are VHF; do not write
    # channels beyond their actual donor band. No generic CS801 support.
    if strict_band:
        offending=[(x['index'],x['name'],x['rx_mhz'],x['tx_mhz']) for x in source['channels']
                   if not 136.0<=x['rx_mhz']<=174.0 or not 136.0<=x['tx_mhz']<=174.0]
        require(not offending,f'CTB has {len(offending)} out-of-band channels for VHF donor: {offending[:5]}')
    require(not any(c['type']=='All' for c in source['contacts']),
            'All Call DMR contact type not verified in destination; refusing incorrect mapping')
    # Binary patcher preserves donor-specific non-programming fields.
    raw,report=patch(source,Path(donor).read_bytes(),model,alias)
    Path(output).write_bytes(raw)
    report.update({'original_ctb_signature_verified':True,'original_ctb_type':metadata['type'],
                   'source_ctb_xml_version':metadata['ctb_xml_version'],
                   'source_analog':sum(c['mode']=='FM' for c in source['channels']),
                   'source_digital':sum(c['mode']=='DMR' for c in source['channels']),
                   'total_scan_members':sum(len(l['members']) for l in source['scan_roam_lists'] if l['type']=='scan'),
                   'total_roaming_members':sum(len(l['members']) for l in source['scan_roam_lists'] if l['type']=='roam'),
                   'unsupported_features':'Motorola QCII not migrated; destination donor two-tone definitions explicitly preserved by user opt-in; security and enhanced encryption not migrated',
                   'source_empty_zones_skipped':'empty default zone placeholders excluded',
                   'source_empty_roaming_scan_skipped':'empty unreferenced placeholder lists excluded'})
    ap=Path(output).with_suffix('.audit.json');ap.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('ctb',type=Path)
    p.add_argument('--config',type=Path,required=True,help='Local [codeplug] AES key/IV config; NEVER bundled with output')
    p.add_argument('--donor',type=Path,required=True,help='Genuine target-model RDB')
    p.add_argument('--model',choices=('CS711','CS811'),required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--alias',default='Imported CTB')
    p.add_argument('--allow-donor-two-tone',action='store_true',help='UNSAFE opt-in: retain donor two-tone definitions (may belong to another person). NEVER use for public conversions.')
    a=p.parse_args()
    if a.output.exists() or a.output.resolve() in (a.ctb.resolve(),a.donor.resolve()):p.error('Output already exists or matches an input file')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    print(json.dumps(convert(a.ctb,a.config,a.donor,a.model,a.output,a.alias,allow_donor_two_tone=a.allow_donor_two_tone),indent=2))
if __name__=='__main__':main()
