import React, { useEffect, useMemo, useState } from "react";
import api from "../lib/api";
import { FilterBar, gravityChip } from "../components/Filters";
import { X, MapPin, User, Files } from "@phosphor-icons/react";

export default function Cases() {
  const [filters, setFilters] = useState({});
  const [query, setQuery] = useState("");
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [skip, setSkip] = useState(0);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const limit = 25;

  const params = useMemo(()=>{
    const p = { limit, skip };
    if (query) p.q = query;
    Object.entries(filters).forEach(([k,v])=>{ if(v && v!=="all") p[k]=v; });
    return p;
  }, [filters, skip, query]);

  useEffect(()=>{
    (async()=>{
      const { data } = await api.get("/cases", { params });
      setItems(data.items); setTotal(data.total);
    })();
  }, [params]);

  useEffect(()=>{
    if (!selected) { setDetail(null); return; }
    (async()=>{
      const { data } = await api.get(`/cases/${selected}`);
      setDetail(data);
    })();
  }, [selected]);

  return (
    <div className="p-4 space-y-3" data-testid="cases-page">
      <div className="flex items-end justify-between">
        <div>
          <div className="overline">FIR Records</div>
          <h1 className="display text-2xl font-bold">Case Explorer</h1>
        </div>
        <div className="flex gap-2 items-center">
          <input data-testid="cases-search" className="input" style={{width:280}} placeholder="Search FIR no, MO, district…"
            value={query} onChange={e=>{ setSkip(0); setQuery(e.target.value); }}/>
        </div>
      </div>

      <FilterBar value={filters} onChange={(f)=>{ setSkip(0); setFilters(f); }}/>

      <div className="grid md:grid-cols-5 gap-[1px] bg-rule">
        <div className="md:col-span-3 bg-base panel">
          <div className="px-3 py-2 border-b border-rule flex justify-between text-xs">
            <span className="overline">Records</span>
            <span className="mono text-sec">{total.toLocaleString()} total</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-sec bg-surface sticky top-0">
                <tr className="border-b border-rule">
                  <th className="text-left p-2 overline">FIR No</th>
                  <th className="text-left p-2 overline">District</th>
                  <th className="text-left p-2 overline">Head</th>
                  <th className="text-left p-2 overline">Gravity</th>
                  <th className="text-left p-2 overline">Status</th>
                  <th className="text-left p-2 overline">Date</th>
                </tr>
              </thead>
              <tbody>
                {items.map(c=>(
                  <tr key={c.id} onClick={()=>setSelected(c.id)}
                    className={`border-b border-rule cursor-pointer hover:bg-surface2 ${selected===c.id?"bg-surface2":""}`}
                    data-testid={`case-row-${c.id}`}>
                    <td className="p-2 mono text-accent">{c.fir_no}</td>
                    <td className="p-2">{c.district}</td>
                    <td className="p-2">{c.crime_head}</td>
                    <td className="p-2"><span className={`chip ${gravityChip(c.gravity)}`}>{c.gravity}</span></td>
                    <td className="p-2 text-sec">{c.status}</td>
                    <td className="p-2 mono text-sec">{c.occurrence_at?.slice(0,10)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex justify-between items-center p-2 text-xs border-t border-rule">
            <span className="mono text-sec">Showing {skip+1}–{Math.min(skip+limit, total)} of {total}</span>
            <div className="flex gap-2">
              <button data-testid="cases-prev" className="btn" disabled={skip===0} onClick={()=>setSkip(Math.max(0,skip-limit))}>Prev</button>
              <button data-testid="cases-next" className="btn" disabled={skip+limit>=total} onClick={()=>setSkip(skip+limit)}>Next</button>
            </div>
          </div>
        </div>

        <div className="md:col-span-2 bg-base panel overflow-auto scrollbar-thin" style={{maxHeight:640}}>
          {!detail ? (
            <div className="p-6 text-sm text-muted">Select a case to view the full FIR breakdown → complainant, victims, accused, arrests, chargesheet, and linked cases.</div>
          ) : (
            <div className="p-3 space-y-3" data-testid="case-detail">
              <div className="flex justify-between items-start">
                <div>
                  <div className="overline">FIR</div>
                  <div className="mono text-accent">{detail.case.fir_no}</div>
                  <div className="display text-lg font-bold">{detail.case.crime_head} · {detail.case.crime_sub_head}</div>
                  <div className="flex items-center gap-1 text-xs text-sec mt-1"><MapPin size={11}/> {detail.case.district} · {detail.case.police_station}</div>
                </div>
                <button onClick={()=>{ setSelected(null); }} className="btn"><X size={12}/></button>
              </div>

              <div className="grid grid-cols-2 gap-[1px] bg-rule">
                <div className="bg-surface p-2">
                  <div className="overline">Gravity</div>
                  <span className={`chip ${gravityChip(detail.case.gravity)} mt-1`}>{detail.case.gravity}</span>
                </div>
                <div className="bg-surface p-2">
                  <div className="overline">Status</div>
                  <div className="text-xs mt-1">{detail.case.status}</div>
                </div>
                <div className="bg-surface p-2">
                  <div className="overline">Occurred</div>
                  <div className="text-xs mono mt-1">{detail.case.occurrence_at?.slice(0,16).replace("T"," ")}</div>
                </div>
                <div className="bg-surface p-2">
                  <div className="overline">Modus Operandi</div>
                  <div className="text-xs mt-1">{detail.case.modus_operandi}</div>
                </div>
              </div>

              <div>
                <div className="overline mb-1">Acts & Sections</div>
                <div className="flex flex-wrap gap-1">
                  {detail.case.acts_sections?.map(s=><span key={s} className="chip">{s}</span>)}
                </div>
              </div>

              <div>
                <div className="overline mb-1"><User size={11} className="inline"/> Complainant</div>
                <div className="text-xs mono">{detail.case.complainant?.name} · {detail.case.complainant?.gender} · {detail.case.complainant?.age}y</div>
              </div>

              <div>
                <div className="overline mb-1">Victims ({detail.case.victims?.length || 0})</div>
                {(detail.case.victims || []).map(v=>(
                  <div key={v.id} className="text-xs mono text-sec">▸ {v.name} · {v.gender} · {v.age}y {v.is_police && <span className="chip chip-crit ml-1">POLICE</span>}</div>
                ))}
              </div>

              <div>
                <div className="overline mb-1">Accused ({detail.case.accused?.length || 0})</div>
                {(detail.case.accused || []).map(a=>(
                  <div key={a.person_id} className="text-xs mono text-sec">
                    ▸ {a.name} · {a.gender} · {a.age}y
                    {a.repeat_offender && <span className="chip chip-crit ml-1">REPEAT</span>}
                  </div>
                ))}
              </div>

              {detail.case.arrests?.length > 0 && (
                <div>
                  <div className="overline mb-1">Arrests</div>
                  {detail.case.arrests.map((a,i)=>(
                    <div key={i} className="text-xs mono text-sec">▸ {a.name} · {a.date?.slice(0,10)} · {a.district}</div>
                  ))}
                </div>
              )}

              {detail.linked_cases?.length > 0 && (
                <div>
                  <div className="overline mb-1"><Files size={11} className="inline"/> Linked Cases (shared accused)</div>
                  {detail.linked_cases.map(l=>(
                    <div key={l.id} className="text-xs mono text-sec">▸ {l.fir_no} · {l.district} · {l.crime_head} · {l.occurrence_at?.slice(0,10)}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
