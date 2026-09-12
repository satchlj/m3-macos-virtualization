#!/usr/bin/env python3
"""Decode an attempt report into one of the three attempt-27 outcomes."""
import json, struct, sys
from pathlib import Path
BASE=0xfffffe0007004000; GETTER=0xfffffe00070bcc98
XNU_LO,XNU_HI=0xfffffe000bfb0000,0xfffffe000c800000
def region_call_sites():
    data=Path('local/payload/sptm.macho').read_bytes(); N=len(data)
    W=lambda o: struct.unpack_from('<I',data,o)[0]
    def cstr(va):
        o=va-BASE
        if not (0<=o<N): return None
        e=data.find(b'\0',o); s=data[o:e].decode('latin1','replace')
        return s if s and all(32<=ord(c)<127 for c in s) else None
    def name_before(oc):
        regs={}
        for off in range(max(0,oc-4*48),oc,4):
            va=BASE+off; w=W(off)
            if (w&0x9f000000)==0x90000000:
                rd=w&31; imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3)
                if imm&(1<<20): imm-=1<<21
                regs[rd]=(va&~0xfff)+(imm<<12)
            elif (w&0xff000000)==0x91000000:
                rd=w&31; rn=(w>>5)&31; imm=(w>>10)&0xfff; sh=(w>>22)&3
                if rn in regs: regs[rd]=regs[rn]+(imm<<(12 if sh==1 else 0))
        return cstr(regs.get(0)) if 0 in regs else None
    sites={}
    for off in range(0x8000,min(N,0x120000),4):
        w=W(off)
        if (w>>26)==0x25:
            imm=w&0x3ffffff
            if imm&(1<<25): imm-=1<<26
            if BASE+off+imm*4==GETTER: sites[BASE+off]=name_before(off)
    return sites
def main(p):
    d=json.load(open(p)); sr=d.get('stop_reason'); print('stop_reason =',sr)
    tr=d.get('trace') or []
    if tr: print('final trace pc = 0x%x  (events=%s)'%(tr[-1]['pc'],d.get('trace_total_events')))
    if d.get('launch'):
        print('*** OUTCOME 2: XNU LAUNCH ***'); print(json.dumps(d['launch'],indent=1)); return
    pn=d.get('sptm_panic')
    if pn:
        print('*** OUTCOME 1: CLEAN SPTM PANIC ***')
        lr=pn.get('lr'); print(' pc=0x%x lr=0x%x'%(pn['pc'],lr))
        print(' args=',[hex(x) for x in (pn.get('args') or [])][:6])
        print(' prior_pcs=',[hex(x) for x in (pn.get('prior_pcs') or [])][-10:])
        sites=region_call_sites()
        # a panic from the getter returns to (call site + 4); find the nearest site at/below lr
        cands=[s for s in sites if s<=lr]
        if cands:
            s=max(cands); print(' nearest getter call site <= lr: 0x%x -> region %r (lr-site=%d)'%(s,sites[s],lr-s))
        return
    if tr and XNU_LO<=tr[-1]['pc']<XNU_HI:
        print('*** OUTCOME 2 (by PC range): in XNU ***'); return
    print('*** OUTCOME 3: ran to budget / other — inspect final PC above ***')
if __name__=='__main__':
    main(sys.argv[1] if len(sys.argv)>1 else 'artifacts/runs/observe-sprr/attempt-27/report.json')
