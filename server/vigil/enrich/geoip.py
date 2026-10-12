"""Offline IP enrichment: country, city/coordinates (when a city database is
present), ASN and network classification.

Ships with DB-IP Lite country (CC BY 4.0) and the public-domain origin-ASN
databases. Drop a GeoLite2-City / dbip-city .mmdb into VIGIL_GEOIP_DIR to get
city-level coordinates (used by impossible-travel detection).
"""
from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path

from ..config import BUNDLED_DATA

log = logging.getLogger("vigil.geoip")

try:
    import maxminddb
except ImportError:  # pragma: no cover
    maxminddb = None

# Approximate country centroids (lat, lon) used for maps and travel-speed
# estimates when only country-level data is available.
CENTROIDS = {
    "AE": (24.0, 54.0), "AR": (-34.0, -64.0), "AT": (47.3, 13.3), "AU": (-25.0, 134.0), "BD": (24.0, 90.0),
    "BE": (50.8, 4.0), "BG": (42.7, 25.5), "BR": (-10.0, -55.0), "BY": (53.7, 27.9), "CA": (56.0, -106.0),
    "CH": (46.8, 8.2), "CL": (-30.0, -71.0), "CN": (35.0, 105.0), "CO": (4.0, -72.0), "CZ": (49.8, 15.5),
    "DE": (51.0, 9.0), "DK": (56.0, 10.0), "DZ": (28.0, 3.0), "EE": (59.0, 26.0), "EG": (27.0, 30.0),
    "ES": (40.0, -4.0), "FI": (64.0, 26.0), "FR": (46.0, 2.0), "GB": (54.0, -2.0), "GR": (39.0, 22.0),
    "HK": (22.3, 114.2), "HU": (47.0, 20.0), "ID": (-5.0, 120.0), "IE": (53.0, -8.0), "IL": (31.5, 34.8),
    "IN": (20.0, 77.0), "IQ": (33.0, 44.0), "IR": (32.0, 53.0), "IT": (42.8, 12.8), "JP": (36.0, 138.0),
    "KE": (1.0, 38.0), "KR": (37.0, 127.5), "KZ": (48.0, 68.0), "LT": (56.0, 24.0), "LU": (49.8, 6.1),
    "LV": (57.0, 25.0), "MA": (32.0, -5.0), "MD": (47.0, 29.0), "MX": (23.0, -102.0), "MY": (2.5, 112.5),
    "NG": (10.0, 8.0), "NL": (52.5, 5.75), "NO": (62.0, 10.0), "NZ": (-41.0, 174.0), "PA": (9.0, -80.0),
    "PE": (-10.0, -76.0), "PH": (13.0, 122.0), "PK": (30.0, 70.0), "PL": (52.0, 20.0), "PT": (39.5, -8.0),
    "RO": (46.0, 25.0), "RS": (44.0, 21.0), "RU": (60.0, 100.0), "SA": (25.0, 45.0), "SC": (-4.6, 55.5),
    "SE": (62.0, 15.0), "SG": (1.37, 103.8), "SK": (48.7, 19.5), "TH": (15.0, 100.0), "TR": (39.0, 35.0),
    "TW": (23.5, 121.0), "UA": (49.0, 32.0), "US": (38.0, -97.0), "UY": (-33.0, -56.0), "UZ": (41.0, 64.0),
    "VE": (8.0, -66.0), "VN": (16.0, 106.0), "ZA": (-29.0, 24.0), "BZ": (17.25, -88.75), "CY": (35.0, 33.0),
    "GE": (42.0, 43.5), "AM": (40.0, 45.0), "AZ": (40.5, 47.5), "IS": (65.0, -18.0), "HR": (45.2, 15.5),
    "SI": (46.1, 14.8), "BA": (44.0, 18.0), "MK": (41.8, 22.0), "AL": (41.0, 20.0), "EC": (-2.0, -77.5),
    "BO": (-17.0, -65.0), "PY": (-23.0, -58.0), "CR": (10.0, -84.0), "GT": (15.5, -90.25), "DO": (19.0, -70.7),
    "CU": (21.5, -80.0), "JM": (18.25, -77.5), "TN": (34.0, 9.0), "LY": (25.0, 17.0), "SD": (15.0, 30.0),
    "ET": (8.0, 38.0), "GH": (8.0, -2.0), "CI": (8.0, -5.0), "SN": (14.0, -14.0), "CM": (6.0, 12.0),
    "TZ": (-6.0, 35.0), "UG": (1.0, 32.0), "AO": (-12.5, 18.5), "ZW": (-20.0, 30.0), "MZ": (-18.25, 35.0),
    "NP": (28.0, 84.0), "LK": (7.0, 81.0), "MM": (22.0, 98.0), "KH": (13.0, 105.0), "LA": (18.0, 105.0),
    "MN": (46.0, 105.0), "QA": (25.5, 51.25), "KW": (29.5, 45.75), "OM": (21.0, 57.0), "JO": (31.0, 36.0),
    "LB": (33.8, 35.8), "SY": (35.0, 38.0), "YE": (15.0, 48.0), "AF": (33.0, 65.0), "KG": (41.0, 75.0),
    "TJ": (39.0, 71.0), "TM": (40.0, 60.0),
}


# RFC 5737 / RFC 3849 documentation ranges: used in examples and the lab replay.
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


class GeoIP:
    def __init__(self, extra_dir: str | None = None):
        self.country = self.city = self.asn = None
        dirs = [Path(extra_dir)] if extra_dir else []
        dirs.append(BUNDLED_DATA)
        if maxminddb is None:
            log.warning("maxminddb not installed; GeoIP enrichment disabled")
            return
        for d in dirs:
            if not d.exists():
                continue
            for f in sorted(d.glob("*.mmdb")):
                try:
                    db = maxminddb.open_database(str(f))
                except Exception as exc:
                    log.warning("cannot open %s: %s", f, exc)
                    continue
                kind = db.metadata().database_type.lower()
                if "asn" in kind and self.asn is None:
                    self.asn = db
                elif "city" in kind and self.city is None:
                    self.city = db
                elif "country" in kind and self.country is None:
                    self.country = db
        log.info("GeoIP: country=%s city=%s asn=%s", bool(self.country), bool(self.city), bool(self.asn))

    @property
    def sources(self) -> dict:
        return {"country": bool(self.country or self.city), "city": bool(self.city), "asn": bool(self.asn)}

    @lru_cache(maxsize=65536)
    def lookup(self, ip: str) -> dict:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {}
        if any(addr in n for n in _DOC_NETS):
            return {"network.type": "documentation"}
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return {"network.type": "internal"}
        out: dict = {"network.type": "external"}
        try:
            rec = self.city.get(ip) if self.city else None
            if rec:
                cc = rec.get("country_code") or (rec.get("country") or {}).get("iso_code")
                loc = rec.get("location") or {}
                lat = rec.get("latitude", loc.get("latitude"))
                lon = rec.get("longitude", loc.get("longitude"))
                city = rec.get("city")
                if isinstance(city, dict):
                    city = (city.get("names") or {}).get("en")
                out.update({"geo.country_iso_code": cc, "geo.city_name": city or None,
                            "geo.location.lat": lat, "geo.location.lon": lon})
            if not out.get("geo.country_iso_code") and self.country:
                rec = self.country.get(ip) or {}
                cc = rec.get("country_code") or (rec.get("country") or {}).get("iso_code")
                out["geo.country_iso_code"] = cc
            cc = out.get("geo.country_iso_code")
            if cc and out.get("geo.location.lat") is None and cc in CENTROIDS:
                out["geo.location.lat"], out["geo.location.lon"] = CENTROIDS[cc]
                out["geo.precision"] = "country"
            if self.asn:
                rec = self.asn.get(ip) or {}
                if rec.get("autonomous_system_number"):
                    out["as.number"] = rec["autonomous_system_number"]
                    out["as.organization.name"] = rec.get("autonomous_system_organization")
        except Exception as exc:  # corrupt db or odd record: never break the pipeline
            log.debug("geoip lookup failed for %s: %s", ip, exc)
        return {k: v for k, v in out.items() if v is not None}

    def enrich(self, ev: dict) -> None:
        ip = ev.get("source.ip")
        if not ip:
            return
        for k, v in self.lookup(str(ip)).items():
            ev[f"source.{k}"] = v
