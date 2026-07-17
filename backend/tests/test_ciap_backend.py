"""CIAP Backend end-to-end API tests using pytest."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://bc96fec0-2d85-4643-94d9-b5060d3c52b7.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

USERS = {
    "admin": ("admin@ksp.gov.in", "Admin@1234", "scrb_admin"),
    "district": ("district@ksp.gov.in", "District@1234", "district_officer"),
    "station": ("station@ksp.gov.in", "Station@1234", "station_officer"),
}


# ---------- Fixtures ----------
@pytest.fixture(scope="session")
def admin_token():
    r = requests.post(f"{API}/auth/login", json={"email": USERS["admin"][0], "password": USERS["admin"][1]}, timeout=30)
    assert r.status_code == 200, f"Admin login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ---------- Health ----------
class TestHealth:
    def test_health(self):
        r = requests.get(f"{API}/health", timeout=15)
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


# ---------- Auth ----------
class TestAuth:
    @pytest.mark.parametrize("key", list(USERS.keys()))
    def test_login_valid_users(self, key):
        email, pw, role = USERS[key]
        r = requests.post(f"{API}/auth/login", json={"email": email, "password": pw}, timeout=30)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "access_token" in data and isinstance(data["access_token"], str)
        assert data["user"]["email"] == email
        assert data["user"]["role"] == role

    def test_login_invalid_credentials(self):
        r = requests.post(f"{API}/auth/login", json={"email": "admin@ksp.gov.in", "password": "wrong"}, timeout=15)
        assert r.status_code == 401

    def test_me_with_token(self, auth_headers):
        r = requests.get(f"{API}/auth/me", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        assert r.json()["email"] == USERS["admin"][0]

    def test_me_without_token(self):
        r = requests.get(f"{API}/auth/me", timeout=15)
        assert r.status_code == 401


# ---------- Reference ----------
class TestReference:
    def test_reference(self, auth_headers):
        r = requests.get(f"{API}/reference", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert len(d["districts"]) == 30
        assert len(d["crime_heads"]) == 8
        assert "Heinous" in d["gravity"]
        assert "Under Investigation" in d["statuses"]


# ---------- Analytics ----------
class TestAnalytics:
    def test_kpi_default(self, auth_headers):
        r = requests.get(f"{API}/analytics/kpi", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        d = r.json()
        for k in ["total_cases", "active_investigations", "chargesheets_filed",
                  "heinous_cases", "total_arrests", "disposal_rate", "week_trend_pct"]:
            assert k in d
        assert 800 <= d["total_cases"] <= 1000, f"Expected ~900 cases, got {d['total_cases']}"

    def test_kpi_filtered_smaller(self, auth_headers):
        r_all = requests.get(f"{API}/analytics/kpi", headers=auth_headers, timeout=30).json()
        r_flt = requests.get(f"{API}/analytics/kpi",
                             headers=auth_headers,
                             params={"district": "Bengaluru Urban", "crime_head": "Cybercrime"},
                             timeout=30).json()
        assert r_flt["total_cases"] < r_all["total_cases"]

    def test_by_district(self, auth_headers):
        r = requests.get(f"{API}/analytics/by_district", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        arr = r.json()
        assert isinstance(arr, list) and len(arr) >= 1
        first = arr[0]
        for k in ["district", "lat", "lng", "count", "crime_rate_per_lakh"]:
            assert k in first

    def test_trends(self, auth_headers):
        r = requests.get(f"{API}/analytics/trends", headers=auth_headers, params={"days": 365}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert "series" in d and "heads" in d
        assert len(d["series"]) >= 1
        assert len(d["heads"]) == 8

    def test_heatmap(self, auth_headers):
        r = requests.get(f"{API}/analytics/heatmap", headers=auth_headers, params={"days": 180}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert "cells" in d
        # 7 days × 24 hours
        assert len(d["cells"]) == 7 * 24

    def test_by_crime_head(self, auth_headers):
        r = requests.get(f"{API}/analytics/by_crime_head", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        arr = r.json()
        assert len(arr) >= 1
        counts = [x["count"] for x in arr]
        assert counts == sorted(counts, reverse=True), "should be desc"

    def test_status_mix(self, auth_headers):
        r = requests.get(f"{API}/analytics/status_mix", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        arr = r.json()
        assert len(arr) >= 1
        assert all("status" in x and "count" in x for x in arr)


# ---------- Predictive ----------
class TestPredict:
    def test_risk(self, auth_headers):
        r = requests.get(f"{API}/predict/risk", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        arr = r.json()
        assert len(arr) == 30
        for row in arr:
            assert 0 <= row["risk_score"] <= 100
            assert row["risk_band"] in ("Low", "Medium", "High", "Critical")
        # verify variance – not all zeros (from problem statement warning)
        distinct = len({round(row["risk_score"], 1) for row in arr})
        assert distinct > 1, "risk_score has no variance"

    def test_anomalies(self, auth_headers):
        r = requests.get(f"{API}/predict/anomalies", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        arr = r.json()
        assert isinstance(arr, list)
        for a in arr:
            for k in ["district", "crime_head", "z_score", "recent_count", "historic_mean"]:
                assert k in a

    def test_clusters(self, auth_headers):
        r = requests.get(f"{API}/predict/clusters", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert "clusters" in d
        if d["clusters"]:
            first = d["clusters"][0]
            for k in ["lat", "lng", "size", "top_crime_head"]:
                assert k in first


# ---------- Network ----------
class TestNetwork:
    def test_graph(self, auth_headers):
        r = requests.get(f"{API}/network/graph", headers=auth_headers, params={"limit": 30}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert "nodes" in d and "links" in d
        types = {n["type"] for n in d["nodes"]}
        # expected types: case, location, suspect, victim, mo
        assert "case" in types
        assert "location" in types

    def test_repeat_offenders(self, auth_headers):
        r = requests.get(f"{API}/network/repeat_offenders", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        arr = r.json()
        assert isinstance(arr, list) and len(arr) >= 1
        assert all(x["case_count"] >= 3 for x in arr)

    def test_offender_detail(self, auth_headers):
        arr = requests.get(f"{API}/network/repeat_offenders", headers=auth_headers, timeout=30).json()
        pid = arr[0]["person_id"]
        r = requests.get(f"{API}/network/offender/{pid}", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert "person" in d and "cases" in d
        assert len(d["cases"]) >= 1


# ---------- Cases ----------
class TestCases:
    def test_cases_list(self, auth_headers):
        r = requests.get(f"{API}/cases", headers=auth_headers, params={"limit": 25, "skip": 0}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert "total" in d and "items" in d
        assert d["total"] >= 800
        assert len(d["items"]) <= 25

    def test_cases_filter_q(self, auth_headers):
        r = requests.get(f"{API}/cases", headers=auth_headers, params={"district": "Bengaluru Urban", "crime_head": "Cybercrime"}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        for it in d["items"]:
            assert it["district"] == "Bengaluru Urban"
            assert it["crime_head"] == "Cybercrime"

    def test_case_detail_valid(self, auth_headers):
        lst = requests.get(f"{API}/cases", headers=auth_headers, params={"limit": 1}, timeout=30).json()
        cid = lst["items"][0]["id"]
        r = requests.get(f"{API}/cases/{cid}", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["case"]["id"] == cid
        assert isinstance(d["linked_cases"], list)

    def test_case_detail_invalid(self, auth_headers):
        r = requests.get(f"{API}/cases/does-not-exist", headers=auth_headers, timeout=15)
        assert r.status_code == 404
