#!/usr/bin/env python3
"""Decode a report's outcome: launch, sptm_panic (resolving strings+site), or budget."""
import json,struct,sys
BASE=0xfffffe0007004000
XNU_LO,XNU_HI=0xfffffe000bfb0000,0xfffffe000c800000
GETTER=0xfffffe00070bcc98
data=open('local/payload/sptm.macho','rb').read(); N=len(data)
def cstr(va):
    o=va-BASE
    if not(0<=o<N): return None
    e=data.find(b'\0',o); s=data[o:e].decode('latin1','replace')
    return s if s else None
def region_sites():
    W=lambda o: struct.unpack_from('<I',data,o)[0]
    def nb(oc):
        regs={}
        for off in range(max(0,oc-4*40),oc,4):
            va=BASE+off; w=W(off)
            if (w&0x9f000000)==0x90000000:
                rd=w&31; imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3); imm-=(1<<21) if imm&(1<<20) else 0; regs[rd]=(va&~0xfff)+(imm<<12)
            elif (w&0xff000000)==0x91000000:
                rd=w&31; rn=(w>>5)&31; im=(w>>10)&0xfff; sh=(w>>22)&3
                if rn in regs: regs[rd]=regs[rn]+(im<<(12 if sh==1 else 0))
            elif (w&0xffe0ffff)==0xaa0003e0:
                xn=(w>>16)&31; xd=w&31; regs[xd]=regs.get(xn)
        return regs.get(0)
    d={}
    for off in range(0x8000,min(N,0x120000),4):
        w=W(off)
        if (w>>26)==0x25:
            i=w&0x3ffffff; i-=(1<<26) if i&(1<<25) else 0
            if BASE+off+i*4==GETTER:
                v=nb(off); s=cstr(v) if v else None
                if s: d[BASE+off]=s
    return d
def main(p):
    d=json.load(open(p)); print("stop_reason:",d.get('stop_reason'),"  events:",d.get('trace_total_events'))
    if d.get('launch'): print("*** XNU LAUNCH ***"); print(json.dumps(d['launch'],indent=1)); return
    od=d.get('on_demand_stage2')
    if od:
        print("on-demand stage-2: mapped %d pages, capped=%s, stage1_faults=%d"%(
            od.get('count',0), od.get('capped'), od.get('stage1_faults',0)))
        for smp in (od.get('samples') or [])[:4]:
            print("   sample va=0x%x ipa=0x%x write=%s"%(smp['va'],smp['ipa'],smp.get('write')))
    pn=d.get('sptm_panic')
    if not pn: print("no panic recorded; final trace pc:",hex(d['trace'][-1]['pc']) if d.get('trace') and 'pc' in d['trace'][-1] else '?'); return
    args=pn.get('args') or []; lr=pn.get('lr')
    print("SPTM PANIC pc=0x%x lr=0x%x"%(pn['pc'],lr))
    fmt=cstr(args[0]) if args else None
    print("  fmt   x0=0x%x  %r"%(args[0],fmt) if args else "  (no args)")
    for i,a in enumerate(args[1:],1):
        s=cstr(a); print("  x%d=0x%x%s"%(i,a,"  %r"%s if s else ""))
    # map lr to nearest getter call site (region) or just show region window
    sites=region_sites(); cands=[x for x in sites if x<=lr]
    if cands:
        s=max(cands); print("  nearest getter site <= lr: 0x%x -> %r (delta %d)"%(s,sites[s],lr-s))
    print("  prior_pcs:",[hex(x) for x in (pn.get('prior_pcs') or [])])
if __name__=='__main__':
    main(sys.argv[1] if len(sys.argv)>1 else 'artifacts/runs/observe-sprr/attempt-29/report.json')
