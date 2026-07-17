import React, { useEffect, useMemo, useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Tooltip as LTooltip } from "react-leaflet";
import api from "../lib/api";
import { FilterBar } from "../components/Filters";

const RISK_COLOR = { Critical: "#F85149", High: "#F78166", Medium: "#D29922", Low: "#3FB950" };

function bandForCount(n, max) {
  const r = n / (max || 1);
  if (r >= 0.75) return "Critical";
  if (r >= 0.5) return "High";
  if (r >= 0.25) return "Medium";
  return "Low";
}

export default function GeoMap() {
  const [filters, setFilters] = useState({ days: 180 });
  const [districts, setDistricts] = useState([]);
  const [clusters, setClusters] = useState([]);
  const [heat, setHeat] = useState(null);
  const [selected, setSelected] = useState(null);

  const params = useMemo(()=>{
    const p={}; Object.entries(filters).forEach(([k,v])=>{ if(v && v!=="all") p[k]=v; }); return p;
  },[filters]);

  useEffect(()=>{
    (async()=>{
      const [d, c, h] = await Promise.all([
        api.get("/analytics/by_district", { params }),
        api.get("/predict/clusters"),
        api.get("/analytics/heatmap", { params: {...params, days: params.days || 180 }}),
      ]);
      setDistricts(d.data); setClusters(c.data.clusters); setHeat(h.data);
    })();
  }, [params]);

  const maxCount = districts[0]?.count || 1;

  return (
    <div className="p-4 space-y-3" data-testid="geo-page">
      <div>
        <div className="overline">Geo Intelligence</div>
        <h1 className="display text-2xl font-bold">Karnataka Crime Hotspot Map</h1>
      </div>

      <FilterBar value={filters} onChange={setFilters} hide={["status"]}/>

      <div className="grid md:grid-cols-4 gap-[1px] bg-rule">
        <div className="md:col-span-3 bg-base panel" style={{height:"560px"}} data-testid="karnataka-map">
          <MapContainer center={[14.9, 76.0]} zoom={7} style={{ height: "100%", width: "100%", background:"#06080A" }}>
            <TileLayer
              attribution='&copy; OpenStreetMap contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            {districts.map(d => {
              const band = bandForCount(d.count, maxCount);
              const color = RISK_COLOR[band];
              const r = 6 + Math.sqrt(d.count) * 1.8;
              return (
                <CircleMarker
                  key={d.district}
                  center={[d.lat, d.lng]}
                  radius={r}
                  pathOptions={{ color, fillColor: color, fillOpacity: 0.35, weight: 1 }}
                  eventHandlers={{ click: ()=>setSelected(d) }}
                >
                  <LTooltip>
                    <div style={{fontFamily:"IBM Plex Sans"}}>
                      <b>{d.district}</b><br/>
                      Cases: {d.count} · Heinous: {d.heinous}<br/>
                      Rate: {d.crime_rate_per_lakh}/lakh
                    </div>
                  </LTooltip>
                </CircleMarker>
              );
            })}
            {clusters.map(c => (
              <CircleMarker
                key={"cl-"+c.id}
                center={[c.lat, c.lng]}
                radius={4 + Math.min(c.size / 12, 20)}
                pathOptions={{ color: "#58A6FF", fillColor: "#58A6FF", fillOpacity: 0.12, dashArray: "3 3", weight: 1 }}
              >
                <LTooltip>
                  <div style={{fontFamily:"IBM Plex Sans"}}>
                    <b>Hotspot #{c.id+1}</b><br/>
                    {c.size} incidents · {c.top_crime_head}<br/>
                    Anchor: {c.top_district}
                  </div>
                </LTooltip>
              </CircleMarker>
            ))}
          </MapContainer>
        </div>

        <div className="bg-base panel p-3 overflow-auto scrollbar-thin" style={{height:"560px"}} data-testid="district-panel">
          <div className="overline mb-2">Legend</div>
          <div className="space-y-1 mb-4">
            {["Critical","High","Medium","Low"].map(b=>(
              <div key={b} className="flex items-center gap-2 text-xs">
                <span className="w-3 h-3 inline-block" style={{background:RISK_COLOR[b]}}/> {b}
              </div>
            ))}
            <div className="flex items-center gap-2 text-xs mt-2">
              <span className="w-3 h-3 inline-block border border-dashed border-accent"/> KMeans Cluster
            </div>
          </div>
          <div className="overline mb-2">District Ranking</div>
          <div className="divide-y divide-rule">
            {districts.slice(0,15).map((d,i)=>(
              <button key={d.district} onClick={()=>setSelected(d)}
                className="w-full text-left py-2 hover:bg-surface2 px-1"
                data-testid={`district-row-${i}`}>
                <div className="flex justify-between text-xs">
                  <span className="text-pri">{d.district}</span>
                  <span className="mono text-sec">{d.count}</span>
                </div>
                <div className="h-1 bg-surface2 mt-1">
                  <div style={{width:(d.count/maxCount*100)+"%", background:RISK_COLOR[bandForCount(d.count, maxCount)], height:"100%"}}/>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {selected && (
        <div className="panel p-3" data-testid="district-selected">
          <div className="flex justify-between items-start">
            <div>
              <div className="overline">Selected District</div>
              <div className="display text-xl font-bold">{selected.district}</div>
            </div>
            <button className="btn" onClick={()=>setSelected(null)}>Close</button>
          </div>
          <div className="grid grid-cols-4 gap-[1px] bg-rule mt-3">
            <div className="bg-surface p-3"><div className="overline">Total Cases</div><div className="mono text-2xl font-bold">{selected.count}</div></div>
            <div className="bg-surface p-3"><div className="overline">Heinous</div><div className="mono text-2xl font-bold text-crit">{selected.heinous}</div></div>
            <div className="bg-surface p-3"><div className="overline">Population</div><div className="mono text-2xl font-bold">{selected.pop_lakh}L</div></div>
            <div className="bg-surface p-3"><div className="overline">Crime / Lakh</div><div className="mono text-2xl font-bold">{selected.crime_rate_per_lakh}</div></div>
          </div>
        </div>
      )}

      {/* Spatiotemporal heatmap grid */}
      <div className="panel" data-testid="heatmap-card">
        <div className="px-3 py-2 border-b border-rule flex justify-between items-center">
          <div className="overline">Spatiotemporal · Day-of-Week × Hour-of-Day</div>
          <span className="chip">{filters.days ? `Last ${filters.days}d` : "Last 180d"}</span>
        </div>
        <div className="p-3 overflow-x-auto">
          <HeatmapGrid data={heat}/>
        </div>
      </div>
    </div>
  );
}

function HeatmapGrid({ data }) {
  if (!data) return <div className="text-sec text-sm">Loading…</div>;
  const grid = {};
  let max = 0;
  const days = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
  data.cells.forEach(c => {
    grid[c.day] = grid[c.day] || {};
    grid[c.day][c.hour] = c.count;
    if (c.count > max) max = c.count;
  });
  return (
    <div>
      <div className="flex text-[9px] text-muted mono mb-1 ml-9">
        {Array.from({length:24}).map((_,h)=>(<div key={h} style={{width:22, textAlign:"center"}}>{h}</div>))}
      </div>
      {days.map(d => (
        <div key={d} className="flex items-center mb-0.5">
          <div className="w-9 text-[10px] mono text-sec">{d}</div>
          {Array.from({length:24}).map((_,h)=>{
            const v = grid[d]?.[h] || 0;
            const t = max ? v/max : 0;
            // interpolate green→yellow→red
            const bg = t < 0.35 ? `rgba(63,185,80,${0.15 + t})` :
                       t < 0.7 ? `rgba(210,153,34,${0.25 + t*0.6})` :
                                 `rgba(248,81,73,${0.35 + t*0.6})`;
            return <div key={h} title={`${d} ${h}:00 → ${v}`} style={{width:22, height:22, background: v ? bg : "#0E1218", marginRight:1, border:"1px solid #161B22"}}/>;
          })}
        </div>
      ))}
    </div>
  );
}
