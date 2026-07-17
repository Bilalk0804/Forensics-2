import React, { useEffect, useState } from "react";
import api from "../lib/api";

export function FilterBar({ value, onChange, hide = [] }) {
  const [ref, setRef] = useState(null);
  useEffect(()=>{ (async()=>{ try{ const {data} = await api.get("/reference"); setRef(data); }catch{} })(); }, []);
  const set = (k,v) => onChange({ ...value, [k]: v });
  const H = (k) => !hide.includes(k);

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-[1px] border border-rule bg-rule mb-3" data-testid="filter-bar">
      {H("district") && (
        <div className="bg-surface p-2">
          <div className="overline mb-1">District</div>
          <select data-testid="filter-district" className="input !p-1.5 text-xs" value={value.district || "all"} onChange={e=>set("district", e.target.value)}>
            <option value="all">All</option>
            {(ref?.districts || []).map(d => <option key={d.name} value={d.name}>{d.name}</option>)}
          </select>
        </div>
      )}
      {H("crime_head") && (
        <div className="bg-surface p-2">
          <div className="overline mb-1">Crime Head</div>
          <select data-testid="filter-crime-head" className="input !p-1.5 text-xs" value={value.crime_head || "all"} onChange={e=>set("crime_head", e.target.value)}>
            <option value="all">All</option>
            {(ref?.crime_heads || []).map(h => <option key={h} value={h}>{h}</option>)}
          </select>
        </div>
      )}
      {H("gravity") && (
        <div className="bg-surface p-2">
          <div className="overline mb-1">Gravity</div>
          <select data-testid="filter-gravity" className="input !p-1.5 text-xs" value={value.gravity || "all"} onChange={e=>set("gravity", e.target.value)}>
            <option value="all">All</option>
            {(ref?.gravity || []).map(g => <option key={g} value={g}>{g}</option>)}
          </select>
        </div>
      )}
      {H("status") && (
        <div className="bg-surface p-2">
          <div className="overline mb-1">Status</div>
          <select data-testid="filter-status" className="input !p-1.5 text-xs" value={value.status || "all"} onChange={e=>set("status", e.target.value)}>
            <option value="all">All</option>
            {(ref?.statuses || []).map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      )}
      {H("days") && (
        <div className="bg-surface p-2">
          <div className="overline mb-1">Window</div>
          <select data-testid="filter-days" className="input !p-1.5 text-xs" value={value.days || ""} onChange={e=>set("days", e.target.value ? Number(e.target.value) : null)}>
            <option value="">All time</option>
            <option value="30">Last 30d</option>
            <option value="90">Last 90d</option>
            <option value="180">Last 180d</option>
            <option value="365">Last 365d</option>
          </select>
        </div>
      )}
    </div>
  );
}

export function riskBandClass(band) {
  return band === "Critical" ? "chip-crit" :
         band === "High" ? "chip-high" :
         band === "Medium" ? "chip-med" : "chip-low";
}

export function gravityChip(g) {
  return g === "Heinous" ? "chip-crit" :
         g === "Cognizable" ? "chip-high" :
         g === "Non-Cognizable" ? "chip-med" : "chip-low";
}
