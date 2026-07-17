import React, { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import api from "../lib/api";
import { FilterBar } from "../components/Filters";

const TYPE_COLOR = {
  case: "#2F81F7",
  suspect: "#F85149",
  victim: "#3FB950",
  location: "#58A6FF",
  mo: "#D29922",
};

export default function Network() {
  const [filters, setFilters] = useState({});
  const [graph, setGraph] = useState({ nodes: [], links: [] });
  const [size, setSize] = useState({ w: 900, h: 560 });
  const containerRef = useRef(null);
  const fgRef = useRef(null);
  const [selected, setSelected] = useState(null);

  const params = useMemo(()=>{
    const p={ limit: 60 }; Object.entries(filters).forEach(([k,v])=>{ if(v && v!=="all") p[k]=v; }); return p;
  },[filters]);

  useEffect(()=>{
    (async()=>{
      const { data } = await api.get("/network/graph", { params });
      setGraph(data);
    })();
  }, [params]);

  useEffect(()=>{
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(entries => {
      for (const e of entries) setSize({ w: e.contentRect.width, h: 560 });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const counts = graph.nodes.reduce((acc,n)=>{ acc[n.type]=(acc[n.type]||0)+1; return acc; }, {});

  return (
    <div className="p-4 space-y-3" data-testid="network-page">
      <div>
        <div className="overline">Link Analysis</div>
        <h1 className="display text-2xl font-bold">Criminological Network Graph</h1>
      </div>
      <FilterBar value={filters} onChange={setFilters} hide={["status","gravity","days"]}/>

      <div className="grid md:grid-cols-4 gap-[1px] bg-rule">
        <div className="md:col-span-3 bg-base panel" ref={containerRef} style={{height: 580}} data-testid="network-canvas">
          <ForceGraph2D
            ref={fgRef}
            graphData={graph}
            width={size.w}
            height={size.h}
            backgroundColor="#06080A"
            nodeRelSize={4}
            linkColor={() => "#2D333B"}
            linkWidth={0.7}
            cooldownTicks={80}
            onNodeClick={(n)=>setSelected(n)}
            nodeCanvasObject={(node, ctx, scale) => {
              const r = node.type === "case" ? 5 : node.type === "mo" ? 3 : 4;
              ctx.fillStyle = TYPE_COLOR[node.type] || "#8B949E";
              if (node.repeat_offender) {
                ctx.beginPath(); ctx.arc(node.x, node.y, r+3, 0, 2*Math.PI);
                ctx.strokeStyle = "#F85149"; ctx.lineWidth = 1.5; ctx.stroke();
              }
              ctx.beginPath(); ctx.arc(node.x, node.y, r, 0, 2*Math.PI); ctx.fill();
              if (scale > 1.3) {
                ctx.font = "10px IBM Plex Sans";
                ctx.fillStyle = "#8B949E";
                ctx.fillText(node.label?.slice(0,18) || "", node.x + r + 3, node.y + 3);
              }
            }}
          />
        </div>

        <div className="bg-base panel p-3 overflow-auto scrollbar-thin" style={{height:580}} data-testid="network-panel">
          <div className="overline mb-2">Legend</div>
          <div className="space-y-1 mb-4">
            {Object.entries(TYPE_COLOR).map(([k,v])=>(
              <div key={k} className="flex items-center gap-2 text-xs">
                <span className="w-3 h-3 inline-block" style={{background:v}}/> {k.toUpperCase()} <span className="mono text-sec ml-auto">{counts[k] || 0}</span>
              </div>
            ))}
            <div className="flex items-center gap-2 text-xs">
              <span className="w-3 h-3 inline-block rounded-full border-2 border-crit"/> REPEAT OFFENDER
            </div>
          </div>

          <div className="overline mb-2">Selected Entity</div>
          {selected ? (
            <div className="text-xs space-y-1">
              <div><span className="text-sec">Type: </span><span className="chip">{selected.type}</span></div>
              <div><span className="text-sec">Label: </span><span className="text-pri">{selected.label}</span></div>
              {selected.crime_head && <div><span className="text-sec">Crime: </span>{selected.crime_head}</div>}
              {selected.district && <div><span className="text-sec">Dist: </span>{selected.district}</div>}
              {selected.repeat_offender && <div className="chip chip-crit mt-2">REPEAT OFFENDER</div>}
            </div>
          ) : <div className="text-xs text-muted">Click any node to inspect</div>}

          <div className="overline mt-6 mb-2">Instructions</div>
          <ul className="text-[11px] text-sec space-y-1 list-disc pl-4">
            <li>Zoom with scroll / pinch</li>
            <li>Drag nodes to untangle clusters</li>
            <li>Filter by district or crime head above</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
