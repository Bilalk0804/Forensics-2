import React, { useEffect, useState } from "react";
import api from "../lib/api";
import { BarChart, Bar, Cell, CartesianGrid, XAxis, YAxis, Tooltip, ResponsiveContainer, ScatterChart, Scatter, ZAxis } from "recharts";

const RISK_COLOR = { Critical: "#F85149", High: "#F78166", Medium: "#D29922", Low: "#3FB950" };

export default function Predictive() {
  const [risk, setRisk] = useState([]);
  const [anom, setAnom] = useState([]);
  const [clusters, setClusters] = useState([]);
  const [selected, setSelected] = useState(null);

  useEffect(()=>{
    (async()=>{
      const [r, a, c] = await Promise.all([
        api.get("/predict/risk"),
        api.get("/predict/anomalies"),
        api.get("/predict/clusters"),
      ]);
      setRisk(r.data); setAnom(a.data); setClusters(c.data.clusters);
    })();
  }, []);

  return (
    <div className="p-4 space-y-3" data-testid="predictive-page">
      <div>
        <div className="overline">AI/ML Intelligence</div>
        <h1 className="display text-2xl font-bold">Predictive Risk & Anomaly Detection</h1>
        <p className="text-sec text-xs mt-1">
          Composite risk = 45% volume · 25% 90d growth · 20% heinous ratio · 10% urbanization · normalized z-score.
        </p>
      </div>

      <div className="grid md:grid-cols-3 gap-[1px] bg-rule">
        <div className="md:col-span-2 bg-base panel">
          <div className="px-3 py-2 border-b border-rule overline">Risk Score by District</div>
          <div className="p-3 h-80">
            <ResponsiveContainer>
              <BarChart data={risk.slice(0,15)}>
                <CartesianGrid stroke="#2D333B" strokeDasharray="2 4"/>
                <XAxis dataKey="district" stroke="#484F58" fontSize={10} angle={-30} textAnchor="end" interval={0} height={70}/>
                <YAxis stroke="#484F58" fontSize={10} domain={[0,100]}/>
                <Tooltip contentStyle={{background:"#0E1218", border:"1px solid #2D333B", fontSize:"12px"}}/>
                <Bar dataKey="risk_score" onClick={(d)=>setSelected(d)}>
                  {risk.slice(0,15).map((r,i)=>(
                    <Cell key={i} fill={RISK_COLOR[r.risk_band]}/>
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-base panel p-3 overflow-auto scrollbar-thin" style={{maxHeight:400}}>
          <div className="overline mb-2">Anomaly Signals (z ≥ 1.8)</div>
          {anom.length === 0 && <div className="text-xs text-muted">No significant anomalies detected.</div>}
          <div className="space-y-2">
            {anom.map((a,i)=>(
              <div key={i} className="border-l-2 border-crit pl-2 py-1" data-testid={`anom-${i}`}>
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium">{a.crime_head}</span>
                  <span className="chip chip-crit">z {a.z_score}</span>
                </div>
                <div className="text-[11px] text-sec">{a.district}</div>
                <div className="mono text-[11px] text-sec">Now {a.recent_count} vs μ {a.historic_mean}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Risk leaderboard full table */}
      <div className="panel" data-testid="risk-table">
        <div className="px-3 py-2 border-b border-rule flex items-center justify-between">
          <div className="overline">Statewide Risk Leaderboard</div>
          <span className="chip">{risk.length} DISTRICTS</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-sec">
              <tr className="border-b border-rule">
                <th className="text-left p-2 overline">Rank</th>
                <th className="text-left p-2 overline">District</th>
                <th className="text-left p-2 overline">Band</th>
                <th className="text-right p-2 overline">Score</th>
                <th className="text-right p-2 overline">Recent 90d</th>
                <th className="text-right p-2 overline">Prev 90d</th>
                <th className="text-right p-2 overline">Growth %</th>
                <th className="text-right p-2 overline">Heinous %</th>
              </tr>
            </thead>
            <tbody className="mono">
              {risk.map((r,i)=>(
                <tr key={r.district} className="border-b border-rule hover:bg-surface2" data-testid={`risk-row-${i}`}>
                  <td className="p-2 text-sec">#{i+1}</td>
                  <td className="p-2 text-pri" style={{fontFamily:"IBM Plex Sans"}}>{r.district}</td>
                  <td className="p-2"><span className={`chip ${r.risk_band==="Critical"?"chip-crit":r.risk_band==="High"?"chip-high":r.risk_band==="Medium"?"chip-med":"chip-low"}`}>{r.risk_band}</span></td>
                  <td className="p-2 text-right font-bold">{r.risk_score}</td>
                  <td className="p-2 text-right">{r.recent_90d}</td>
                  <td className="p-2 text-right text-sec">{r.prev_90d}</td>
                  <td className={`p-2 text-right ${r.growth_pct>=0?"text-crit":"text-low"}`}>{r.growth_pct>0?"+":""}{r.growth_pct}%</td>
                  <td className="p-2 text-right">{r.heinous_ratio}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Cluster explorer scatter */}
      <div className="panel" data-testid="cluster-scatter">
        <div className="px-3 py-2 border-b border-rule overline">Spatial Cluster Discovery · KMeans (180d)</div>
        <div className="p-3 h-72">
          <ResponsiveContainer>
            <ScatterChart>
              <CartesianGrid stroke="#2D333B" strokeDasharray="2 4"/>
              <XAxis type="number" dataKey="lng" stroke="#484F58" fontSize={10} domain={['auto','auto']} name="Lng"/>
              <YAxis type="number" dataKey="lat" stroke="#484F58" fontSize={10} domain={['auto','auto']} name="Lat"/>
              <ZAxis type="number" dataKey="size" range={[50, 600]} name="Size"/>
              <Tooltip cursor={{ strokeDasharray: '3 3' }}
                contentStyle={{background:"#0E1218", border:"1px solid #2D333B", fontSize:"12px"}}
                content={({active, payload})=>{
                  if(!active || !payload?.length) return null;
                  const p = payload[0].payload;
                  return <div className="panel p-2 text-xs mono">
                    <div className="text-pri">Cluster #{p.id+1}</div>
                    <div>Size: {p.size}</div>
                    <div>Top head: {p.top_crime_head}</div>
                    <div>Anchor: {p.top_district}</div>
                  </div>;
                }}
              />
              <Scatter data={clusters} fill="#2F81F7"/>
            </ScatterChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
