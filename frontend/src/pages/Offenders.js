import React, { useEffect, useState } from "react";
import api from "../lib/api";
import { WarningOctagon, MapPin } from "@phosphor-icons/react";

export default function Offenders() {
  const [list, setList] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);

  useEffect(()=>{
    (async()=>{
      const { data } = await api.get("/network/repeat_offenders");
      setList(data);
      if (data[0]) setSelected(data[0].person_id);
    })();
  }, []);

  useEffect(()=>{
    if (!selected) return;
    (async()=>{
      const { data } = await api.get(`/network/offender/${selected}`);
      setDetail(data);
    })();
  }, [selected]);

  return (
    <div className="p-4 space-y-3" data-testid="offenders-page">
      <div>
        <div className="overline">Behavioural Analysis</div>
        <h1 className="display text-2xl font-bold">Repeat Offender Registry</h1>
        <p className="text-sec text-xs mt-1">Individuals linked to 3+ cases — cross-jurisdictional pattern discovery & MO fingerprinting.</p>
      </div>

      <div className="grid md:grid-cols-5 gap-[1px] bg-rule">
        <div className="md:col-span-2 bg-base panel overflow-auto scrollbar-thin" style={{maxHeight:680}}>
          <div className="px-3 py-2 border-b border-rule flex justify-between">
            <span className="overline">Registry</span>
            <span className="mono text-sec text-xs">{list.length} profiles</span>
          </div>
          <div>
            {list.map((r,i)=>(
              <button key={r.person_id} onClick={()=>setSelected(r.person_id)}
                data-testid={`offender-row-${i}`}
                className={`w-full text-left px-3 py-3 border-b border-rule hover:bg-surface2 ${selected===r.person_id?"bg-surface2 border-l-2 border-l-crit":""}`}>
                <div className="flex justify-between items-start">
                  <div className="text-sm font-medium">{r.name}</div>
                  <div className="mono text-xs text-crit">{r.case_count} cases</div>
                </div>
                <div className="text-[11px] text-sec mono mt-1"><MapPin size={10} className="inline"/> {r.district_count} jurisdictions</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {r.crime_heads?.slice(0,3).map(h=><span key={h} className="chip">{h}</span>)}
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="md:col-span-3 bg-base panel p-4 overflow-auto scrollbar-thin" style={{maxHeight:680}}>
          {!detail ? <div className="text-sec text-sm">Select an offender to view dossier.</div> : (
            <div className="space-y-3" data-testid="offender-detail">
              <div className="flex items-start justify-between">
                <div>
                  <div className="overline">Dossier</div>
                  <div className="display text-2xl font-bold">{detail.person?.name}</div>
                  <div className="text-xs mono text-sec">
                    ID {detail.person?.id?.slice(0,8)} · {detail.person?.gender} · {detail.person?.age}y · {detail.person?.home_district}
                  </div>
                </div>
                <span className="chip chip-crit"><WarningOctagon size={11}/> REPEAT OFFENDER</span>
              </div>

              <div className="grid grid-cols-4 gap-[1px] bg-rule">
                <div className="bg-surface p-2">
                  <div className="overline">Cases</div>
                  <div className="mono text-xl font-bold">{detail.cases?.length}</div>
                </div>
                <div className="bg-surface p-2">
                  <div className="overline">Jurisdictions</div>
                  <div className="mono text-xl font-bold">{new Set(detail.cases?.map(c=>c.district)).size}</div>
                </div>
                <div className="bg-surface p-2">
                  <div className="overline">Categories</div>
                  <div className="mono text-xl font-bold">{new Set(detail.cases?.map(c=>c.crime_head)).size}</div>
                </div>
                <div className="bg-surface p-2">
                  <div className="overline">Signature MO</div>
                  <div className="text-xs mt-1">{detail.person?.signature_mo?.join(", ")}</div>
                </div>
              </div>

              <div>
                <div className="overline mb-2">Case Timeline</div>
                <div className="space-y-1">
                  {detail.cases?.map(c=>(
                    <div key={c.id} className="grid grid-cols-12 gap-2 py-1.5 border-b border-rule text-xs" data-testid={`offender-case-${c.id}`}>
                      <div className="col-span-2 mono text-sec">{c.occurrence_at?.slice(0,10)}</div>
                      <div className="col-span-2 mono text-accent">{c.fir_no}</div>
                      <div className="col-span-3">{c.crime_head}</div>
                      <div className="col-span-2 text-sec">{c.district}</div>
                      <div className="col-span-2 text-sec truncate">{c.modus_operandi}</div>
                      <div className="col-span-1"><span className="chip">{c.status?.split(" ")[0]}</span></div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
