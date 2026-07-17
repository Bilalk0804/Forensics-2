import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { formatDetail } from "../lib/api";
import { Shield, LockKey, Warning } from "@phosphor-icons/react";

export default function Login() {
  const nav = useNavigate();
  const { login } = useAuth();
  const [email, setEmail] = useState("admin@ksp.gov.in");
  const [password, setPassword] = useState("Admin@1234");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setErr(""); setLoading(true);
    try { await login(email, password); nav("/", { replace: true }); }
    catch (ex) { setErr(formatDetail(ex.response?.data?.detail) || ex.message); }
    setLoading(false);
  };

  return (
    <div className="min-h-screen w-full flex" data-testid="login-page">
      <div className="hidden md:flex md:w-3/5 relative overflow-hidden panel border-r">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_30%,rgba(47,129,247,0.12),transparent_60%),radial-gradient(circle_at_80%_70%,rgba(248,81,73,0.10),transparent_55%)]" />
        <div className="absolute inset-0" style={{
          backgroundImage: "linear-gradient(rgba(45,51,59,0.35) 1px, transparent 1px), linear-gradient(90deg, rgba(45,51,59,0.35) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}/>
        <div className="relative z-10 flex flex-col justify-between p-10 w-full">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 flex items-center justify-center bg-accent text-base"><Shield size={20} weight="fill"/></div>
            <div>
              <div className="display font-black tracking-wider">CIAP</div>
              <div className="overline">Crime Intelligence & Analytical Platform</div>
            </div>
          </div>
          <div className="max-w-lg">
            <div className="overline mb-3">Karnataka State Police · SCRB</div>
            <h1 className="display text-5xl font-black leading-[1.05] mb-4">From reactive reporting to <span className="text-accent">tactical intelligence</span>.</h1>
            <p className="text-sec text-sm leading-relaxed">Unify FIR records, discover spatiotemporal hotspots, expose repeat offender networks, and forecast emerging crime typologies — all in one command console.</p>
            <div className="grid grid-cols-3 gap-[1px] mt-8 border border-rule">
              {[
                {k:"CASES", v:"900+"},
                {k:"DISTRICTS", v:"30"},
                {k:"AI SIGNALS", v:"LIVE"},
              ].map((s)=>(
                <div key={s.k} className="bg-surface p-4">
                  <div className="overline">{s.k}</div>
                  <div className="mono text-2xl font-bold mt-1">{s.v}</div>
                </div>
              ))}
            </div>
          </div>
          <div className="overline">Restricted · Authorised personnel only</div>
        </div>
      </div>

      <div className="flex-1 flex items-center justify-center bg-base p-6">
        <form onSubmit={submit} className="w-full max-w-md panel p-8" data-testid="login-form">
          <div className="overline mb-1">Secure Access</div>
          <h2 className="display text-2xl font-bold mb-6">Sign in to Command Console</h2>

          <label className="overline block mb-1">Officer Email</label>
          <input data-testid="login-email" className="input mb-4" value={email} onChange={e=>setEmail(e.target.value)} placeholder="you@ksp.gov.in" />

          <label className="overline block mb-1">Password</label>
          <div className="relative mb-4">
            <input data-testid="login-password" type="password" className="input pr-9" value={password} onChange={e=>setPassword(e.target.value)} />
            <LockKey size={16} className="absolute right-2 top-2.5 text-muted"/>
          </div>

          {err && (
            <div className="flex items-start gap-2 border border-crit/70 bg-crit/10 p-2 mb-3 text-crit text-xs" data-testid="login-error">
              <Warning size={14} className="mt-0.5"/> <span>{err}</span>
            </div>
          )}

          <button data-testid="login-submit" disabled={loading} className="btn btn-primary w-full">
            {loading ? "Authenticating…" : "Authenticate"}
          </button>

          <div className="mt-6 border-t border-rule pt-4">
            <div className="overline mb-2">Demo Credentials</div>
            <div className="grid gap-2 text-xs mono text-sec">
              <button type="button" className="text-left hover:text-pri" onClick={()=>{setEmail("admin@ksp.gov.in");setPassword("Admin@1234");}}>▸ SCRB Admin — admin@ksp.gov.in / Admin@1234</button>
              <button type="button" className="text-left hover:text-pri" onClick={()=>{setEmail("district@ksp.gov.in");setPassword("District@1234");}}>▸ District Officer — district@ksp.gov.in / District@1234</button>
              <button type="button" className="text-left hover:text-pri" onClick={()=>{setEmail("station@ksp.gov.in");setPassword("Station@1234");}}>▸ Station Officer — station@ksp.gov.in / Station@1234</button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
