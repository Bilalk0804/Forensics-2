import React, { useEffect, useMemo, useState } from "react";
import api from "../lib/api";
import { FilterBar, gravityChip } from "../components/Filters";
import { ArrowUpRight, ArrowDownRight, WarningDiamond, Pulse, Gavel, User, FileMagnifyingGlass, ChartPieSlice } from "@phosphor-icons/react";
import { BarChart, Bar, LineChart, Line, AreaChart, Area, XAxis, YAxis, ResponsiveContainer, Tooltip, CartesianGrid, PieChart, Pie, Cell, Legend } from "recharts";

const COLORS = ["#2F81F7", "#F85149", "#D29922", "#3FB950", "#A371F7", "#F78166", "#58A6FF", "#DB61A2"];

function Card({ title, right, children, testid }) {
  return (
    <div className="panel" data-testid={testid}>
      <div className="flex items-center justify-between px-3 py-2 border-b border-rule">
        <div className="overline">{title}</div>
        {right}
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}

function KPI({ label, value, delta, icon: Icon, testid, tone="neutral" }) {
  const up = delta != null && delta >= 0;
  return (
    <div className="panel p-3" data-testid={testid}>
      <div className="flex items-center justify-between">
        <div className="overline">{label}</div>
        {Icon && <Icon size={14} className="text-sec"/>}
      </div>
      <div className="mono font-bold text-3xl mt-2 text-pri">{value}</div>
      {delta != null && (
        <div className={`mt-1 text-[11px] flex items-center gap-1 mono ${up ? "text-crit" : "text-low"}`}>
          {up ? <ArrowUpRight size={12}/> : <ArrowDownRight size={12}/>} {Math.abs(delta).toFixed(1)}% wow
        </div>
      )}
    </div>
  );
}

export default function Dashboard() {
  const [filters, setFilters] = useState({});
  const [kpi, setKpi] = useState(null);
  const [byDistrict, setByDistrict] = useState([]);
  const [trends, setTrends] = useState(null);
  const [heads, setHeads] = useState([]);
  const [statusMix, setStatusMix] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [risk, setRisk] = useState([]);

  const params = useMemo(() => {
    const p = {};
    Object.entries(filters).forEach(([k,v]) => { if (v && v !== "all") p[k]=v; });
    return p;
  }, [filters]);

  useEffect(()=>{
    (async () => {
      try {
        const [k, bd, tr, bh, sm, an, rk] = await Promise.all([
          api.get("/analytics/kpi", { params }),
          api.get("/analytics/by_district", { params }),
          api.get("/analytics/trends", { params: { ...params, days: 365 }}),
          api.get("/analytics/by_crime_head", { params }),
          api.get("/analytics/status_mix", { params }),
          api.get("/predict/anomalies"),
          api.get("/predict/risk"),
        ]);
        setKpi(k.data); setByDistrict(bd.data); setTrends(tr.data);
        setHeads(bh.data); setStatusMix(sm.data); setAnomalies(an.data); setRisk(rk.data);
      } catch (e) { console.error(e); }
    })();
  }, [params]);

  const topDistricts = byDistrict.slice(0, 8);
  const criticalDistricts = risk.filter(r => r.risk_band === "Critical").slice(0, 5);

  return (
    <div className="p-4 space-y-3" data-testid="dashboard-page">
      <div className="flex items-center justify-between">
        <div>
          <div className="overline">Executive Overview</div>
          <h1 className="display text-2xl font-bold">State-wide Crime Intelligence</h1>
        </div>
      </div>

      <FilterBar value={filters} onChange={setFilters} />

      {/* KPI Row */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-[1px] bg-rule border border-rule">
        <KPI label="Total FIRs" value={kpi?.total_cases ?? "—"} icon={FileMagnifyingGlass} testid="kpi-total" delta={kpi?.week_trend_pct}/>
        <KPI label="Under Investigation" value={kpi?.active_investigations ?? "—"} icon={ChartPieSlice} testid="kpi-active"/>
        <KPI label="Chargesheets" value={kpi?.chargesheets_filed ?? "—"} icon={Gavel} testid="kpi-chargesheet"/>
        <KPI label="Heinous" value={kpi?.heinous_cases ?? "—"} icon={WarningDiamond} testid="kpi-heinous"/>
        <KPI label="Arrests" value={kpi?.total_arrests ?? "—"} icon={User} testid="kpi-arrests"/>
        <KPI label="Disposal Rate" value={(kpi?.disposal_rate ?? 0) + "%"} icon={Pulse} testid="kpi-disposal"/>
      </div>

      {/* Emerging Trend Alerts */}
      {anomalies.length > 0 && (
        <Card title="Emerging Trend Alerts · Red-Zone" testid="alerts-card"
          right={<div className="chip chip-crit animate-pulseRed">{anomalies.length} SIGNALS</div>}>
          <div className="grid md:grid-cols-3 gap-[1px] bg-rule">
            {anomalies.slice(0,6).map((a,i)=>(
              <div key={i} className="bg-surface p-3 border-l-2 border-crit relative overflow-hidden" data-testid={`alert-${i}`}>
                <div className="flex items-center justify-between">
                  <div className="chip chip-crit">{a.severity}</div>
                  <div className="mono text-[11px] text-sec">z={a.z_score}</div>
                </div>
                <div className="display font-bold mt-2">{a.crime_head}</div>
                <div className="text-sec text-xs">↑ Spike in <span className="text-pri">{a.district}</span></div>
                <div className="mt-2 mono text-[11px] text-sec">
                  Now <span className="text-pri">{a.recent_count}</span> · Norm <span className="text-muted">{a.historic_mean}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Trends + Status + Heads */}
      <div className="grid md:grid-cols-3 gap-[1px] bg-rule">
        <div className="md:col-span-2 bg-base">
          <Card title="Crime Volume — Monthly Trend by Category" testid="trends-card">
            <div className="h-72">
              <ResponsiveContainer>
                <AreaChart data={trends?.series || []}>
                  <defs>
                    {(trends?.heads || []).map((h,i)=>(
                      <linearGradient id={`g-${i}`} key={h} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={COLORS[i%COLORS.length]} stopOpacity={0.35}/>
                        <stop offset="100%" stopColor={COLORS[i%COLORS.length]} stopOpacity={0}/>
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid stroke="#2D333B" strokeDasharray="2 4"/>
                  <XAxis dataKey="month" stroke="#484F58" fontSize={10}/>
                  <YAxis stroke="#484F58" fontSize={10}/>
                  <Tooltip contentStyle={{ background:"#0E1218", border:"1px solid #2D333B", fontSize:"12px" }}/>
                  {(trends?.heads || []).slice(0,5).map((h,i)=>(
                    <Area key={h} type="monotone" dataKey={h} stroke={COLORS[i%COLORS.length]} fill={`url(#g-${i})`} strokeWidth={1.5}/>
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
        <div className="bg-base">
          <Card title="Case Status Mix" testid="status-mix-card">
            <div className="h-72">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={statusMix} dataKey="count" nameKey="status" innerRadius={45} outerRadius={80} strokeWidth={1} stroke="#0E1218">
                    {statusMix.map((_,i)=><Cell key={i} fill={COLORS[i%COLORS.length]}/>)}
                  </Pie>
                  <Tooltip contentStyle={{ background:"#0E1218", border:"1px solid #2D333B", fontSize:"12px" }}/>
                  <Legend wrapperStyle={{fontSize:"10px", color:"#8B949E"}}/>
                </PieChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
      </div>

      {/* Top districts + Crime heads + Critical districts */}
      <div className="grid md:grid-cols-3 gap-[1px] bg-rule">
        <div className="bg-base md:col-span-2">
          <Card title="Top Districts by Volume" testid="top-districts-card">
            <div className="h-72">
              <ResponsiveContainer>
                <BarChart data={topDistricts} layout="vertical" margin={{left:20}}>
                  <CartesianGrid stroke="#2D333B" strokeDasharray="2 4"/>
                  <XAxis type="number" stroke="#484F58" fontSize={10}/>
                  <YAxis type="category" dataKey="district" stroke="#484F58" fontSize={10} width={140}/>
                  <Tooltip contentStyle={{ background:"#0E1218", border:"1px solid #2D333B", fontSize:"12px" }}/>
                  <Bar dataKey="count" fill="#2F81F7"/>
                  <Bar dataKey="heinous" fill="#F85149"/>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
        <div className="bg-base">
          <Card title="Volume by Crime Head" testid="head-mix-card">
            <div className="space-y-1.5">
              {heads.slice(0,8).map((h,i)=>{
                const max = heads[0]?.count || 1;
                const pct = Math.round((h.count/max)*100);
                return (
                  <div key={h.crime_head} data-testid={`head-row-${i}`}>
                    <div className="flex justify-between text-xs mb-0.5">
                      <span>{h.crime_head}</span>
                      <span className="mono text-sec">{h.count}</span>
                    </div>
                    <div className="h-1.5 bg-surface2 relative">
                      <div className="absolute inset-y-0 left-0" style={{width:pct+"%", background:COLORS[i%COLORS.length]}}/>
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>
        </div>
      </div>

      {/* AI risk leaderboard preview */}
      <Card title="AI Risk Leaderboard · Critical Districts (Next 90d)" testid="risk-leaderboard-card"
        right={<span className="chip">Statistical Model</span>}>
        <div className="grid md:grid-cols-5 gap-[1px] bg-rule">
          {risk.slice(0,5).map((r,i)=>(
            <div key={r.district} className="bg-surface p-3 relative" data-testid={`risk-card-${i}`}>
              <div className="flex items-center justify-between">
                <span className={`chip ${r.risk_band==="Critical"?"chip-crit":r.risk_band==="High"?"chip-high":r.risk_band==="Medium"?"chip-med":"chip-low"}`}>{r.risk_band}</span>
                <span className="mono text-2xl font-bold">{r.risk_score}</span>
              </div>
              <div className="display mt-2 font-bold">{r.district}</div>
              <div className="text-[11px] text-sec mono mt-1">↑ {r.growth_pct}% growth · {r.heinous_ratio}% heinous</div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
