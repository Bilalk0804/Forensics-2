import React from "react";
import { Outlet, NavLink, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { Shield, ChartPieSlice, MapTrifold, ShareNetwork, Brain, FileText, UserFocus, SignOut, ArrowClockwise } from "@phosphor-icons/react";

const NAV = [
  { to: "/", label: "Command", icon: ChartPieSlice, testid: "nav-dashboard", end: true },
  { to: "/map", label: "Geo Intel", icon: MapTrifold, testid: "nav-map" },
  { to: "/network", label: "Network", icon: ShareNetwork, testid: "nav-network" },
  { to: "/predictive", label: "Predictive", icon: Brain, testid: "nav-predictive" },
  { to: "/cases", label: "Case Explorer", icon: FileText, testid: "nav-cases" },
  { to: "/offenders", label: "Repeat Offenders", icon: UserFocus, testid: "nav-offenders" },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const loc = useLocation();
  const currentTitle = NAV.find(n => n.to === loc.pathname)?.label || "Command";
  const now = new Date().toISOString().replace("T"," ").slice(0,19)+" UTC";

  return (
    <div className="min-h-screen w-screen flex bg-base" data-testid="app-shell">
      {/* Sidebar */}
      <aside className="w-56 border-r border-rule bg-surface flex flex-col" data-testid="sidebar">
        <div className="p-4 border-b border-rule flex items-center gap-2">
          <div className="w-8 h-8 flex items-center justify-center bg-accent text-base"><Shield size={18} weight="fill"/></div>
          <div>
            <div className="display font-black leading-none tracking-wider">CIAP</div>
            <div className="overline mt-1" style={{fontSize:"9px"}}>KSP · SCRB</div>
          </div>
        </div>
        <nav className="flex-1 py-2">
          {NAV.map(n => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              data-testid={n.testid}
              className={({isActive})=>`flex items-center gap-3 px-4 py-2.5 text-[13px] border-l-2 ${
                isActive ? "border-accent bg-surface2 text-pri" : "border-transparent text-sec hover:text-pri hover:bg-surface2"
              }`}
            >
              <n.icon size={16} weight="regular" />
              <span>{n.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-rule">
          <div className="overline mb-1">Signed in</div>
          <div className="text-sm truncate" data-testid="user-name">{user?.name}</div>
          <div className="text-[11px] mono text-sec truncate">{user?.email}</div>
          <div className="chip mt-2" data-testid="user-role">{user?.role?.replace("_"," ")}</div>
          <button data-testid="logout-btn" onClick={logout} className="btn w-full mt-3 flex items-center justify-center gap-2">
            <SignOut size={13}/> Sign out
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col min-w-0">
        <header className="border-b border-rule bg-surface flex items-center justify-between px-5 py-3" data-testid="topbar">
          <div className="flex items-center gap-3">
            <div className="overline">STATION // {currentTitle}</div>
            <div className="chip chip-low"><span className="w-1.5 h-1.5 bg-low rounded-full animate-pulse"/> LIVE</div>
          </div>
          <div className="flex items-center gap-4">
            <div className="mono text-[11px] text-sec" data-testid="clock">{now}</div>
            <button onClick={()=>window.location.reload()} className="btn flex items-center gap-1.5" data-testid="reload-btn">
              <ArrowClockwise size={12}/> Refresh
            </button>
          </div>
        </header>
        <div className="flex-1 overflow-auto scrollbar-thin">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
