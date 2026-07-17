import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "sonner";
import { AuthProvider, useAuth } from "./context/AuthContext";
import Login from "./pages/Login";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import GeoMap from "./pages/GeoMap";
import Network from "./pages/Network";
import Predictive from "./pages/Predictive";
import Cases from "./pages/Cases";
import Offenders from "./pages/Offenders";

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="p-8 text-sec">Authenticating…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster theme="dark" position="top-right" />
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Protected><Layout /></Protected>}>
            <Route index element={<Dashboard />} />
            <Route path="map" element={<GeoMap />} />
            <Route path="network" element={<Network />} />
            <Route path="predictive" element={<Predictive />} />
            <Route path="cases" element={<Cases />} />
            <Route path="offenders" element={<Offenders />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
