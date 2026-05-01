"""
OPEN INTEL — Dark Web OSINT Platform
Features: Dark web search, paste monitoring, breach validator,
          Tor identity rotation, real-time monitoring, AI analysis
"""

import os
import streamlit as st
import threading, json, re, time, hashlib
from datetime import datetime
from urllib.parse import quote
from streamlit.runtime.scriptrunner import add_script_run_ctx

# ── Load environment variables from .env file ─────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed — will use sidebar input or env vars directly

from search import get_search_results
from scrape import scrape_multiple, scrape_paste_sites, check_hibp, rotate_tor_identity
from surface_web import (
    whois_lookup, dns_recon, subdomain_enum, ip_intelligence,
    username_hunt, generate_dorks, search_dork, wayback_lookup,
    email_osint, phone_intel, cert_transparency, tech_fingerprint,
    threat_intel_lookup,
    social_media_from_domain, robots_and_sitemap,
    asn_reputation, zone_transfer_check, security_audit,
)

# ── API Key — loaded from .env or entered via sidebar UI ──────────────────────
# Priority: Sidebar input > .env file > environment variable
_ENV_GROQ_KEY = os.getenv("GROQ_API_KEY", "")

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="OPEN INTEL",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Session State Init ────────────────────────────────────────────────────────
for key, default in {
    "monitor_active": False,
    "monitor_results": [],
    "monitor_log": [],
    "monitor_kw": "",
    "scan_history": [],
    "last_scan": None,
    "tor_rotations": 0,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# ── Report builder (used by scan + reports tab) ───────────────────────────────
def _build_report(q, found_links, scraped, relevant, ai_text=None):
    n = len(relevant)
    risk = ("🔴 CRITICAL" if n>15 else "🟠 HIGH" if n>8 else "🟡 MEDIUM" if n>3 else "🟢 LOW")
    r  = f"# 🕵️ OPEN INTEL — Dark Web Intelligence Report\n"
    r += f"## Target: `{q}`\n"
    r += f"## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n---\n\n"
    r += f"## Executive Summary\n| Metric | Value |\n|---|---|\n"
    r += f"| Target | `{q}` |\n| Sources Discovered | {len(found_links)} |\n"
    r += f"| Sites Scraped | {len([v for v in scraped.values() if len(v)>100])} |\n"
    r += f"| Relevant Mentions | {n} |\n| Risk Level | **{risk}** |\n\n---\n\n"
    r += f"## Discovered Sources ({len(found_links)})\n\n"
    for i, s in enumerate(found_links[:30], 1):
        r += f"{i}. **{s.get('title','—')}**\n   `{s.get('link','')}`\n\n"
    r += f"---\n\n## Relevant Findings ({n})\n\n"
    for i, f in enumerate(relevant, 1):
        r += f"### Finding #{i}\n**Source:** `{f['url']}`\n**Mentions:** {f.get('mention_count',1)}×\n\n"
        r += f"```\n{f['snippet'][:500]}\n```\n\n---\n\n"
    r += f"## AI Threat Analysis\n{ai_text or '*Not available*'}\n\n"
    r += f"---\n**Classification:** CONFIDENTIAL | **Tool:** OPEN INTEL\n"
    return r


# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background: #050d1a; color: #c8d8ec; }

/* ── Header ── */
.hero {
    background: linear-gradient(135deg, #050d1a 0%, #0a1f3a 50%, #050d1a 100%);
    border: 1px solid #0d3060;
    border-radius: 16px;
    padding: 32px;
    text-align: center;
    margin-bottom: 28px;
    position: relative;
    overflow: hidden;
}
.hero::before {
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: radial-gradient(circle at 50% 50%, rgba(0,180,255,0.04) 0%, transparent 60%);
}
.hero-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2.8rem;
    color: #00b4ff;
    text-shadow: 0 0 30px rgba(0,180,255,0.5), 0 0 60px rgba(0,180,255,0.2);
    letter-spacing: 6px;
    margin: 0 0 8px 0;
}
.hero-sub {
    color: #3a6a9a;
    font-size: 0.9rem;
    letter-spacing: 3px;
    text-transform: uppercase;
}
.hero-badges {
    display: flex;
    justify-content: center;
    gap: 10px;
    margin-top: 16px;
    flex-wrap: wrap;
}
.hbadge {
    background: rgba(0,180,255,0.08);
    border: 1px solid rgba(0,180,255,0.2);
    color: #00b4ff;
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 11px;
    letter-spacing: 1px;
}

/* ── Metric Cards ── */
.metric-row { display: flex; gap: 12px; margin: 16px 0; flex-wrap: wrap; }
.mcard {
    background: #080f1e;
    border: 1px solid #0d2a4a;
    border-radius: 12px;
    padding: 16px 20px;
    flex: 1;
    min-width: 120px;
    text-align: center;
    transition: border-color 0.3s;
}
.mcard:hover { border-color: #00b4ff; }
.mcard-val {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.8rem;
    color: #00b4ff;
    text-shadow: 0 0 10px rgba(0,180,255,0.3);
    line-height: 1;
}
.mcard-lbl { font-size: 11px; color: #2a5a8a; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }

/* ── Risk Badges ── */
.risk-critical { background:#2d0a0a; border:1px solid #ef4444; color:#ef4444; border-radius:8px; padding:10px 16px; font-weight:700; text-align:center; }
.risk-high     { background:#2d1a0a; border:1px solid #f97316; color:#f97316; border-radius:8px; padding:10px 16px; font-weight:700; text-align:center; }
.risk-medium   { background:#2d280a; border:1px solid #eab308; color:#eab308; border-radius:8px; padding:10px 16px; font-weight:700; text-align:center; }
.risk-low      { background:#0a2d1a; border:1px solid #22c55e; color:#22c55e; border-radius:8px; padding:10px 16px; font-weight:700; text-align:center; }

/* ── Cards ── */
.finding-card {
    background: #080f1e;
    border: 1px solid #0d2a4a;
    border-left: 3px solid #00b4ff;
    border-radius: 10px;
    padding: 14px 16px;
    margin: 8px 0;
}
.paste-card {
    background: #080f1e;
    border: 1px solid #0d2a4a;
    border-left: 3px solid #a78bfa;
    border-radius: 10px;
    padding: 14px 16px;
    margin: 8px 0;
}
.breach-safe { background:#0a2d1a; border:1px solid #22c55e; border-radius:10px; padding:14px; margin:6px 0; }
.breach-hit  { background:#2d0a0a; border:1px solid #ef4444; border-radius:10px; padding:14px; margin:6px 0; }
.breach-unk  { background:#1a1a2d; border:1px solid #6b7280; border-radius:10px; padding:14px; margin:6px 0; }

.monitor-live {
    background: #080f1e;
    border: 1px solid #22c55e;
    border-radius: 10px;
    padding: 12px 16px;
    margin: 6px 0;
    animation: pulse-border 2s infinite;
}
@keyframes pulse-border {
    0%,100% { border-color: #22c55e; }
    50%      { border-color: #16a34a; }
}
.log-line {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: #3a7a5a;
    padding: 2px 0;
    border-bottom: 1px solid #0a1a10;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: #06101f !important;
    border-right: 1px solid #0d2a4a;
}
.sidebar-section {
    background: #080f1e;
    border: 1px solid #0d2a4a;
    border-radius: 10px;
    padding: 12px;
    margin: 10px 0;
}
.tor-badge {
    background: linear-gradient(135deg,#0a2d1a,#0d3820);
    border: 1px solid #22c55e;
    border-radius: 8px;
    padding: 10px;
    text-align: center;
    color: #22c55e;
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    margin: 8px 0;
}
.warn-box {
    background: #1a1200;
    border: 1px solid #854d0e;
    border-radius: 8px;
    padding: 10px;
    text-align: center;
    color: #fbbf24;
    font-size: 12px;
    font-weight: 600;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: #080f1e;
    border-radius: 10px;
    padding: 4px;
    border: 1px solid #0d2a4a;
    gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    background: transparent;
    color: #3a6a9a;
    border-radius: 8px;
    font-weight: 500;
    padding: 8px 16px;
}
.stTabs [aria-selected="true"] {
    background: #00b4ff !important;
    color: #050d1a !important;
    font-weight: 700 !important;
}

/* ── Input ── */
.stTextInput input {
    background: #080f1e !important;
    border: 1px solid #0d2a4a !important;
    color: #c8d8ec !important;
    border-radius: 10px !important;
    font-family: 'Share Tech Mono', monospace !important;
}
.stTextInput input:focus {
    border-color: #00b4ff !important;
    box-shadow: 0 0 0 2px rgba(0,180,255,0.15) !important;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg,#0047ab,#0066cc) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    font-weight: 600 !important;
    transition: all 0.2s !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg,#0055cc,#0077ee) !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 15px rgba(0,100,200,0.3) !important;
}

#MainMenu, footer, .stDeployButton { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ── Hero Header ───────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
  <div class="hero-title">🕵️ OPEN INTEL</div>
  <div class="hero-sub">Full-Spectrum OSINT Intelligence Platform · Surface &amp; Dark Web</div>
  <div class="hero-badges">
    <span class="hbadge">🧅 TOR ROUTED</span>
    <span class="hbadge">🌐 SURFACE WEB</span>
    <span class="hbadge">🔍 DORKING ENGINE</span>
    <span class="hbadge">📋 PASTE MONITORING</span>
    <span class="hbadge">🔐 BREACH VALIDATOR</span>
    <span class="hbadge">🦠 THREAT INTEL</span>
    <span class="hbadge">🌍 IP / WHOIS / DNS</span>
    <span class="hbadge">👤 USERNAME HUNT</span>
    <span class="hbadge">🤖 AI ANALYSIS</span>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="warn-box">⚠️ FOR EDUCATIONAL USE ONLY<br>Authorized Research Only</div>', unsafe_allow_html=True)

    # Tor Status
    st.markdown("---")
    st.markdown('<div class="tor-badge">🧅 TOR PROXY ACTIVE<br>socks5h://127.0.0.1:9050</div>', unsafe_allow_html=True)

    if st.button("🔄 Rotate Tor Identity", use_container_width=True):
        with st.spinner("Requesting new circuit..."):
            ok = rotate_tor_identity()
            if ok:
                st.session_state.tor_rotations += 1
                st.success(f"✅ New identity #{st.session_state.tor_rotations}")
            else:
                st.warning("⚠️ Tor control unavailable\n(Normal if ControlPort not set)")

    st.markdown(f"**Rotations this session:** `{st.session_state.tor_rotations}`")

    # ── Groq API Key ──────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🤖 AI Configuration")
    _sidebar_key = st.text_input(
        "Groq API Key",
        type="password",
        placeholder="gsk_... (paste your key here)",
        value="",
        help="Get a free key at console.groq.com · Key is never stored or logged"
    )
    GROQ_API_KEY = _sidebar_key.strip() if _sidebar_key.strip() else _ENV_GROQ_KEY

    if GROQ_API_KEY:
        st.markdown(
            "<div style="background:#0a2d1a;border:1px solid #22c55e;border-radius:6px;"
            "padding:6px 10px;font-size:11px;color:#22c55e;text-align:center">"
            "✅ API Key Active</div>",
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            "<div style="background:#1a1200;border:1px solid #854d0e;border-radius:6px;"
            "padding:6px 10px;font-size:11px;color:#fbbf24;text-align:center">"
            "⚠️ No API Key — AI Analysis disabled<br>"
            "<a href="https://console.groq.com" target="_blank" "
            "style="color:#60a5fa">Get free key →</a></div>",
            unsafe_allow_html=True
        )

    # Settings
    st.markdown("---")
    st.markdown("### ⚙️ Settings")
    threads        = st.slider("Scrape Threads",   5, 50, 20)
    max_links      = st.slider("Max Links",        5, 50, 15)
    search_workers = st.slider("Search Workers",   5, 18, 12)

    st.markdown("---")
    st.markdown("### 🎯 Options")
    do_paste   = st.checkbox("Paste Site Monitoring",     True)
    do_ai      = st.checkbox("AI Threat Analysis",        True)
    do_dedup   = st.checkbox("Filter Duplicate Domains",  True)
    do_report  = st.checkbox("Generate Full Report",      True)

    # History
    if st.session_state.scan_history:
        st.markdown("---")
        st.markdown("### 🕘 Recent Scans")
        for h in st.session_state.scan_history[-5:][::-1]:
            st.markdown(
                f"<div style='font-size:12px;color:#3a6a9a;padding:3px 0;border-bottom:1px solid #0d2a4a'>"
                f"<span style='color:#00b4ff'>{h['query']}</span> "
                f"<span style='color:#22c55e'>{h['found']} found</span></div>",
                unsafe_allow_html=True
            )

# ═════════════════════════════════════════════════════════════════════
# TABS
# ═════════════════════════════════════════════════════════════════════
(tab_scan, tab_paste, tab_breach, tab_monitor, tab_report,
 tab_surface, tab_domain, tab_identity, tab_threat) = st.tabs([
    "🚀 Dark Web Scan",
    "📋 Paste Monitor",
    "🔐 Breach Validator",
    "📡 Real-Time Monitor",
    "📄 Reports",
    "🌐 Surface Web OSINT",
    "🔍 Domain & IP Intel",
    "👤 Identity OSINT",
    "🦠 Threat Intel",
])


# ══════════════════════════════════════════════════════
#  TAB 1 — DARK WEB SCAN
# ══════════════════════════════════════════════════════
with tab_scan:
    st.markdown("### 🔍 Search Target")
    c1, c2 = st.columns([5, 1])
    with c1:
        query = st.text_input(
            "target", label_visibility="collapsed",
            placeholder="Enter keyword, company, CVE, username, email, hash…",
            key="scan_query"
        )
    with c2:
        scan_btn = st.button("🚀 SCAN", type="primary", use_container_width=True)

    with st.expander("💡 Search Examples"):
        a, b, c = st.columns(3)
        a.markdown("**🦠 Threats**\n- LockBit ransomware\n- CVE-2024-1234\n- APT28\n- 0day exploit")
        b.markdown("**💾 Breaches**\n- company.com breach\n- credential dump\n- leaked database\n- combolist")
        c.markdown("**🔍 OSINT**\n- email@domain.com\n- username osint\n- bitcoin wallet\n- RDP access")

    if scan_btn and query:
        q = query.strip()

        # ── Phase 1: Search ──────────────────────────────────
        with st.status("🔍 Querying 17 dark web search engines via Tor…", expanded=True) as status:
            st.write(f"🎯 **Target:** `{q}`")

            found_links = get_search_results(q.replace(" ", "+"), max_workers=search_workers)

            if not found_links:
                st.error("❌ No results found. Check: `sudo service tor start`")
                status.update(label="❌ No results", state="error")
                st.stop()

            st.success(f"✅ **{len(found_links)}** sources discovered")

            # Dedup
            if do_dedup:
                seen_d, deduped = set(), []
                for item in found_links:
                    m = re.search(r'http[s]?://([a-z0-9]{16,56}\.onion)', item['link'])
                    if m:
                        d = m.group(1)
                        if d not in seen_d: seen_d.add(d); deduped.append(item)
                found_links = deduped
                st.info(f"📊 After deduplication: **{len(found_links)}** unique domains")

            to_scrape = found_links[:max_links]

            with st.expander(f"🔗 {len(to_scrape)} links queued for scraping"):
                for i, item in enumerate(to_scrape, 1):
                    st.markdown(f"**{i}.** {item['title']}")
                    st.code(item['link'], language=None)

        # ── Phase 2: Scrape ──────────────────────────────────
        with st.status("🔥 Scraping sites via Tor…", expanded=True) as status2:
            prog = st.progress(0)
            add_script_run_ctx(threading.current_thread())
            scraped = scrape_multiple(to_scrape, max_workers=threads)
            prog.progress(100)
            ok   = len([v for v in scraped.values() if len(v) > 100])
            rate = ok / len(to_scrape) * 100 if to_scrape else 0
            kb   = sum(len(v) for v in scraped.values()) // 1000
            st.success(f"✅ **{ok}/{len(to_scrape)}** scraped ({rate:.0f}%) · **{kb} KB** collected")
            status2.update(label="✅ Scraping complete", state="complete")

        # ── Metrics ──────────────────────────────────────────
        st.markdown("---")
        n = len(found_links)
        risk_html = (
            '<div class="risk-critical">🔴 CRITICAL RISK — High volume of dark web mentions</div>' if n > 15 else
            '<div class="risk-high">🟠 HIGH RISK — Multiple mentions found</div>'    if n > 8  else
            '<div class="risk-medium">🟡 MEDIUM RISK — Limited mentions detected</div>' if n > 3  else
            '<div class="risk-low">🟢 LOW RISK — Minimal exposure detected</div>'
        )
        st.markdown(risk_html, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="metric-row">
          <div class="mcard"><div class="mcard-val">{len(found_links)}</div><div class="mcard-lbl">Sources Found</div></div>
          <div class="mcard"><div class="mcard-val">{ok}</div><div class="mcard-lbl">Scraped</div></div>
          <div class="mcard"><div class="mcard-val">{rate:.0f}%</div><div class="mcard-lbl">Success Rate</div></div>
          <div class="mcard"><div class="mcard-val">{kb}KB</div><div class="mcard-lbl">Data Collected</div></div>
        </div>
        """, unsafe_allow_html=True)

        # ── Relevance ─────────────────────────────────────────
        relevant = []
        kw = q.lower()
        for url, content in scraped.items():
            if kw in content.lower():
                count = content.lower().count(kw)
                idx   = content.lower().find(kw)
                snip  = content[max(0,idx-250):idx+300]
                relevant.append({"url":url,"snippet":snip,"full_content":content,"mention_count":count})
        relevant.sort(key=lambda x: x["mention_count"], reverse=True)

        if relevant:
            total_m = sum(f["mention_count"] for f in relevant)
            st.markdown(f"### 🎯 {len(relevant)} Relevant Sources — {total_m} Total Mentions")
            for i, f in enumerate(relevant, 1):
                st.markdown(
                    f"<div class='finding-card'>"
                    f"<div style='font-family:monospace;font-size:12px;color:#a78bfa'>#{i} · {f['url']}</div>"
                    f"<div style='font-size:12px;color:#3a6a9a;margin:4px 0'>Mentions: <b style=\"color:#00b4ff\">{f['mention_count']}×</b></div>"
                    f"</div>", unsafe_allow_html=True
                )
                st.text_area("", f["snippet"], height=80, key=f"snip_{i}", label_visibility="collapsed")
        else:
            st.warning(f"⚠️ No direct mentions of `{q}` in scraped content.")

        # ── AI Analysis ───────────────────────────────────────
        ai_text = None
        if do_ai and relevant:
            st.markdown("### 🤖 AI Threat Analysis")
            with st.spinner("🧠 LLaMA-3.3-70B analyzing findings…"):
                try:
                    from agno.agent import Agent
                    from agno.models.groq import Groq
                    agent = Agent(
                        model=Groq(id="llama-3.3-70b-versatile", api_key=GROQ_API_KEY),
                        role="Senior Threat Intelligence Analyst",
                        instructions=[
                            f"Target: {q}. Analyze the dark web findings below.",
                            "Categorize threat type: Breach/Credentials/Ransomware/Market/APT/Hacktivist.",
                            "Assign severity: CRITICAL / HIGH / MEDIUM / LOW with justification.",
                            "List key IOCs found (IPs, domains, hashes, usernames, emails).",
                            "Give exactly 5 concrete actionable defensive recommendations.",
                            "Format with markdown headers. Be precise and concise."
                        ]
                    )
                    brief = f"**Target:** {q}\n**Sources with mentions:** {len(relevant)}\n\n"
                    for i, f in enumerate(relevant[:6], 1):
                        brief += f"\n--- SOURCE {i} ({f['url']}) ---\n{f['full_content'][:700]}\n"
                    ai_text = agent.run(brief).content
                    st.markdown(ai_text)
                except Exception as e:
                    st.error(f"AI analysis failed: {e}")

        # Save to history + session
        st.session_state.scan_history.append({
            "query": q, "found": len(found_links), "relevant": len(relevant),
            "time": datetime.now().strftime("%H:%M:%S"), "ai": ai_text,
            "scraped": scraped, "found_links": found_links, "relevant_data": relevant
        })
        st.session_state.last_scan = st.session_state.scan_history[-1]

        # ── Report Preview ────────────────────────────────────
        if do_report and relevant:
            st.markdown("---\n### 📄 Download Report")
            report = _build_report(q, found_links, scraped, relevant, ai_text)
            ts = datetime.now().strftime('%Y%m%d_%H%M')
            d1, d2, d3 = st.columns(3)
            d1.download_button("📥 Full Report (.md)", report, f"intel_{q}_{ts}.md", "text/markdown")
            d2.download_button("📊 JSON Export",
                               json.dumps({"target":q,"found":len(found_links),"relevant":len(relevant),
                                           "findings":[{"url":f["url"],"mentions":f["mention_count"],
                                                        "snippet":f["snippet"]} for f in relevant]}, indent=2),
                               f"intel_{q}_{ts}.json", "application/json")
            d3.download_button("🔗 URLs List", "\n".join(i['link'] for i in to_scrape),
                               f"urls_{q}_{ts}.txt", "text/plain")


# ══════════════════════════════════════════════════════
#  TAB 2 — PASTE MONITOR
# ══════════════════════════════════════════════════════
with tab_paste:
    st.markdown("### 📋 Paste Site Monitoring")
    st.markdown("Searches **Pastebin**, **ControlC** and other paste sites for your keyword. No Tor needed.")

    pc1, pc2 = st.columns([5, 1])
    with pc1:
        paste_query = st.text_input("paste_q", label_visibility="collapsed",
                                    placeholder="Enter email, company, username, API key, domain…",
                                    key="paste_query")
    with pc2:
        paste_btn = st.button("🔍 SEARCH PASTES", use_container_width=True)

    st.markdown("""
    **What gets detected:**
    - Leaked credentials & combo lists
    - Exposed API keys & tokens
    - Internal company data leaks
    - Source code leaks
    - Configuration files
    """)

    if paste_btn and paste_query:
        pq = paste_query.strip()
        with st.spinner(f"🔍 Scanning paste sites for `{pq}`…"):
            findings = scrape_paste_sites(pq)

        if findings:
            st.success(f"🚨 **{len(findings)} pastes** found mentioning `{pq}`!")
            for i, f in enumerate(findings, 1):
                src_color = "#a78bfa" if "pastebin" in f["source"] else "#34d399"
                st.markdown(
                    f"<div class='paste-card'>"
                    f"<div style='font-size:11px;color:{src_color};font-weight:700;text-transform:uppercase'>"
                    f"📋 {f['source']}</div>"
                    f"<div style='font-family:monospace;font-size:12px;color:#60a5fa;margin:4px 0'>{f['url']}</div>"
                    f"<div style='font-size:12px;color:#3a6a9a'>Mentions: <b style=\"color:#ef4444\">{f['mention_count']}×</b></div>"
                    f"</div>", unsafe_allow_html=True
                )
                st.text_area("", f["snippet"], height=90, key=f"paste_{i}", label_visibility="collapsed")
                st.markdown("---")
        else:
            st.info(f"✅ No paste mentions found for `{pq}` — this is good!")
            st.markdown("_Paste sites may rate-limit searches. Try again in a few minutes if needed._")


# ══════════════════════════════════════════════════════
#  TAB 3 — BREACH VALIDATOR
# ══════════════════════════════════════════════════════
with tab_breach:
    st.markdown("### 🔐 Breach Credential Validator")
    st.markdown("Check if emails appear in known data breaches via **HaveIBeenPwned**.")

    breach_input = st.text_area(
        "emails",
        label_visibility="collapsed",
        placeholder="Enter emails to check (one per line):\nexample@gmail.com\nuser@company.com\nadmin@domain.org",
        height=150,
        key="breach_emails"
    )
    breach_btn = st.button("🔐 CHECK BREACHES", type="primary", use_container_width=False)

    if breach_btn and breach_input:
        emails = [e.strip() for e in breach_input.strip().splitlines() if "@" in e.strip()]
        if not emails:
            st.warning("Please enter valid email addresses.")
        else:
            st.markdown(f"### Checking {len(emails)} email(s)…")

            total_hit, total_safe = 0, 0
            results_data = []

            for email in emails:
                with st.spinner(f"Checking `{email}`…"):
                    result = check_hibp(email)
                    time.sleep(1.6)  # HIBP rate limit: 1 request per 1.5s

                results_data.append({"email": email, **result})

                found_status = result.get("found")
                src_label    = result.get("source", "")
                note_label   = result.get("note", "")

                if found_status is True:
                    total_hit += 1
                    breach_list = ", ".join(result.get("breaches",[])) if result.get("breaches") else "Unknown breach"
                    bc = result.get("breach_count", 1)
                    st.markdown(
                        "<div class='breach-hit'>"
                        "<div style='font-weight:700;color:#ef4444;font-size:14px'>🚨 BREACHED: " + email + "</div>"
                        "<div style='font-size:12px;color:#fca5a5;margin-top:6px'>"
                        "Found in <b>" + str(bc) + "</b> breach(es) &nbsp;"
                        "<span style='background:rgba(239,68,68,0.15);border:1px solid #ef4444;"
                        "border-radius:4px;padding:1px 6px;font-size:10px;color:#ef4444'>" + src_label + "</span></div>"
                        "<div style='font-size:11px;color:#94a3b8;margin-top:6px'>"
                        "<b>Sources:</b> " + breach_list + "</div>"
                        + ("<div style='font-size:10px;color:#6b7280;margin-top:4px'>" + note_label + "</div>" if note_label else "") +
                        "</div>",
                        unsafe_allow_html=True
                    )
                elif found_status is False:
                    total_safe += 1
                    st.markdown(
                        "<div class='breach-safe'>"
                        "<div style='font-weight:700;color:#22c55e;font-size:14px'>✅ SAFE: " + email + "</div>"
                        "<div style='font-size:12px;color:#86efac;margin-top:4px'>"
                        "Not found in any known breach databases &nbsp;"
                        "<span style='background:rgba(34,197,94,0.15);border:1px solid #22c55e;"
                        "border-radius:4px;padding:1px 6px;font-size:10px;color:#22c55e'>" + src_label + "</span>"
                        "</div></div>",
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        "<div class='breach-unk'>"
                        "<div style='font-weight:700;color:#6b7280;font-size:14px'>❓ UNKNOWN: " + email + "</div>"
                        "<div style='font-size:12px;color:#9ca3af;margin-top:4px'>"
                        "Could not determine status</div></div>",
                        unsafe_allow_html=True
                    )

            # Summary
            st.markdown("---")
            st.markdown(f"""
            <div class="metric-row">
              <div class="mcard"><div class="mcard-val">{len(emails)}</div><div class="mcard-lbl">Checked</div></div>
              <div class="mcard" style="border-color:#ef4444"><div class="mcard-val" style="color:#ef4444">{total_hit}</div><div class="mcard-lbl">Breached</div></div>
              <div class="mcard" style="border-color:#22c55e"><div class="mcard-val" style="color:#22c55e">{total_safe}</div><div class="mcard-lbl">Safe</div></div>
            </div>
            """, unsafe_allow_html=True)

            if total_hit > 0:
                report_lines = [f"# Breach Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"]
                for r in results_data:
                    status = "BREACHED" if r.get("found") else "SAFE"
                    report_lines.append(f"## {r['email']} — {status}")
                    if r.get("found"):
                        report_lines.append(f"Breaches: {', '.join(r.get('breaches',[]))}\n")
                st.download_button("📥 Download Breach Report", "\n".join(report_lines),
                                   f"breach_report_{datetime.now().strftime('%Y%m%d')}.md")


# ══════════════════════════════════════════════════════
#  TAB 4 — REAL-TIME MONITOR
# ══════════════════════════════════════════════════════
with tab_monitor:
    st.markdown("### 📡 Real-Time Dark Web Monitor")
    st.markdown("Continuously scans for new mentions of your target. Runs in background and alerts on new findings.")

    mc1, mc2 = st.columns([4, 1])
    with mc1:
        monitor_query = st.text_input("mon_q", label_visibility="collapsed",
                                      placeholder="Keyword to monitor continuously…",
                                      key="mon_input")
    with mc2:
        interval = st.selectbox("Interval", ["5 min","10 min","15 min","30 min"], index=1)

    col_start, col_stop = st.columns(2)
    with col_start:
        start_btn = st.button("▶ START MONITORING", type="primary", use_container_width=True,
                              disabled=st.session_state.monitor_active)
    with col_stop:
        stop_btn  = st.button("⏹ STOP MONITORING", use_container_width=True,
                              disabled=not st.session_state.monitor_active)

    # Status indicator
    if st.session_state.monitor_active:
        st.markdown(
            f"<div class='monitor-live'>🟢 <b>LIVE</b> — Monitoring "
            f"<code style='color:#00b4ff'>{st.session_state.get('monitor_kw','...')}</code> "
            f"every {interval} · Scans: <b>{len(st.session_state.monitor_log)}</b></div>",
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            "<div style='background:#080f1e;border:1px solid #0d2a4a;border-radius:10px;"
            "padding:12px;color:#3a6a9a;text-align:center'>⬤ MONITOR INACTIVE</div>",
            unsafe_allow_html=True
        )

    if start_btn and monitor_query:
        st.session_state.monitor_active  = True
        # Store query in a separate key (NOT same as widget key "monitor_query")
        st.session_state.monitor_kw      = monitor_query
        st.session_state.monitor_interval = {"5 min":300,"10 min":600,"15 min":900,"30 min":1800}[interval]
        st.session_state.monitor_results = []
        st.session_state.monitor_log     = []

        def monitor_worker():
            seen_hashes   = set()
            scan_count    = 0
            kw            = st.session_state.monitor_kw
            interval_secs = st.session_state.monitor_interval
            while st.session_state.get("monitor_active", False):
                scan_count += 1
                ts = datetime.now().strftime("%H:%M:%S")
                st.session_state.monitor_log.append(f"[{ts}] Scan #{scan_count} — target: '{kw}'")
                try:
                    links   = get_search_results(kw.replace(" ","+"), max_workers=8)
                    scraped = scrape_multiple(links[:10], max_workers=10)
                    new_found = 0
                    for url, content in scraped.items():
                        if kw.lower() in content.lower():
                            h = hashlib.md5((url+content[:200]).encode()).hexdigest()
                            if h not in seen_hashes:
                                seen_hashes.add(h)
                                idx  = content.lower().find(kw.lower())
                                snip = content[max(0,idx-150):idx+200]
                                st.session_state.monitor_results.append({
                                    "url":url,"snippet":snip,"time":ts,"scan":scan_count
                                })
                                new_found += 1
                    st.session_state.monitor_log.append(
                        f"[{ts}] Scan #{scan_count} complete — {len(links)} sources, {new_found} NEW findings"
                    )
                except Exception as e:
                    st.session_state.monitor_log.append(f"[{ts}] Scan #{scan_count} ERROR: {e}")

                for _ in range(interval_secs):
                    if not st.session_state.get("monitor_active", False): break
                    time.sleep(1)

        t = threading.Thread(target=monitor_worker, daemon=True)
        add_script_run_ctx(t)
        t.start()
        st.rerun()

    if stop_btn:
        st.session_state.monitor_active = False
        st.success("⏹ Monitoring stopped.")
        st.rerun()

    # Show findings
    if st.session_state.monitor_results:
        st.markdown(f"### 🚨 {len(st.session_state.monitor_results)} New Findings")
        for f in reversed(st.session_state.monitor_results[-20:]):
            st.markdown(
                f"<div class='finding-card'>"
                f"<div style='font-size:10px;color:#22c55e;font-family:monospace'>"
                f"⏱ {f['time']} · Scan #{f['scan']}</div>"
                f"<div style='font-family:monospace;font-size:12px;color:#60a5fa;margin:4px 0'>{f['url']}</div>"
                f"<div style='font-size:12px;color:#94a3b8'>{f['snippet'][:200]}…</div>"
                f"</div>", unsafe_allow_html=True
            )
        if st.button("🗑 Clear Findings"):
            st.session_state.monitor_results = []
            st.rerun()

    # Activity log
    if st.session_state.monitor_log:
        with st.expander("📋 Activity Log"):
            log_html = "".join(
                f"<div class='log-line'>{line}</div>"
                for line in reversed(st.session_state.monitor_log[-30:])
            )
            st.markdown(log_html, unsafe_allow_html=True)

    if st.session_state.monitor_active:
        time.sleep(2)
        st.rerun()


# ══════════════════════════════════════════════════════
#  TAB 5 — REPORTS
# ══════════════════════════════════════════════════════
with tab_report:
    st.markdown("### 📄 Intelligence Reports")

    if not st.session_state.scan_history:
        st.info("📭 No scans yet. Run a scan first in the **Dark Web Scan** tab.")
    else:
        st.markdown(f"**{len(st.session_state.scan_history)}** scans this session")

        for i, scan in enumerate(reversed(st.session_state.scan_history), 1):
            with st.expander(f"📊 Scan #{len(st.session_state.scan_history)-i+1} — `{scan['query']}` — {scan['time']}"):
                st.markdown(f"""
                <div class="metric-row">
                  <div class="mcard"><div class="mcard-val">{scan['found']}</div><div class="mcard-lbl">Found</div></div>
                  <div class="mcard"><div class="mcard-val">{scan['relevant']}</div><div class="mcard-lbl">Relevant</div></div>
                  <div class="mcard"><div class="mcard-val">{scan['time']}</div><div class="mcard-lbl">Time</div></div>
                </div>
                """, unsafe_allow_html=True)

                if scan.get("ai"):
                    st.markdown("**AI Analysis:**")
                    st.markdown(scan["ai"])

                if scan.get("relevant_data"):
                    report = _build_report(
                        scan["query"], scan["found_links"],
                        scan["scraped"], scan["relevant_data"], scan.get("ai")
                    )
                    ts = datetime.now().strftime('%Y%m%d_%H%M')
                    st.download_button(
                        f"📥 Download Report", report,
                        f"intel_{scan['query']}_{ts}.md",
                        "text/markdown", key=f"dl_{i}"
                    )





# ══════════════════════════════════════════════════════
#  TAB 6 — SURFACE WEB OSINT (Google Dorking Engine)
# ══════════════════════════════════════════════════════
with tab_surface:
    st.markdown("### 🌐 Surface Web OSINT — Advanced Dorking Engine")
    st.markdown(
        "Generates targeted dork queries across **8 attack categories** and executes them "
        "live via DuckDuckGo. No API key required."
    )

    sw_c1, sw_c2 = st.columns([4, 1])
    with sw_c1:
        sw_query = st.text_input(
            "sw_q", label_visibility="collapsed",
            placeholder="Target: domain.com · company name · email · person · CVE…",
            key="sw_input"
        )
    with sw_c2:
        sw_btn = st.button("🔍 GENERATE DORKS", type="primary", use_container_width=True)

    # Category filter
    all_cats = ["Exposed Files", "Login Panels", "Sensitive Data",
                "Subdomains & Dev", "CVE / Exploits", "People / Social",
                "Infrastructure", "Historical"]
    selected_cats = st.multiselect(
        "Dork Categories", all_cats, default=all_cats,
        key="sw_cats"
    )

    execute_dorks = st.checkbox(
        "⚡ Auto-execute selected dorks (DuckDuckGo live search)", value=False,
        key="sw_exec"
    )
    max_execute = st.slider("Max dorks to execute", 1, 10, 3, key="sw_max_exec") \
        if execute_dorks else 3

    if sw_btn and sw_query:
        target = sw_query.strip()
        dork_data = generate_dorks(target)
        dorks_flat = []
        for cat in selected_cats:
            for d in dork_data["dorks"].get(cat, []):
                dorks_flat.append((cat, d))

        st.markdown(f"""
        <div class="metric-row">
          <div class="mcard"><div class="mcard-val">{len(dorks_flat)}</div><div class="mcard-lbl">Dorks Generated</div></div>
          <div class="mcard"><div class="mcard-val">{len(selected_cats)}</div><div class="mcard-lbl">Categories</div></div>
          <div class="mcard"><div class="mcard-val">{len(all_cats)}</div><div class="mcard-lbl">Total Available</div></div>
        </div>
        """, unsafe_allow_html=True)

        # Download all dorks as text
        dork_txt = f"# OPEN INTEL — Dork Report for: {target}\n"
        dork_txt += f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        for cat, d in dorks_flat:
            dork_txt += f"## {cat}\n{d}\n\n"
        st.download_button("📥 Download All Dorks", dork_txt,
                           f"dorks_{target}_{datetime.now().strftime('%Y%m%d')}.txt",
                           "text/plain")

        # Category-grouped display
        for cat in selected_cats:
            cat_dorks = dork_data["dorks"].get(cat, [])
            if not cat_dorks:
                continue

            cat_colors = {
                "Exposed Files":   "#ef4444",
                "Login Panels":    "#f97316",
                "Sensitive Data":  "#dc2626",
                "Subdomains & Dev":"#3b82f6",
                "CVE / Exploits":  "#a855f7",
                "People / Social": "#06b6d4",
                "Infrastructure":  "#84cc16",
                "Historical":      "#78716c",
            }
            color = cat_colors.get(cat, "#00b4ff")

            with st.expander(f"**{cat}** — {len(cat_dorks)} dorks", expanded=(cat == "Exposed Files")):
                for i, dork in enumerate(cat_dorks):
                    col_dork, col_copy = st.columns([7, 1])
                    with col_dork:
                        st.markdown(
                            f"<div style='background:#080f1e;border:1px solid #0d2a4a;"
                            f"border-left:3px solid {color};border-radius:8px;padding:8px 12px;"
                            f"font-family:monospace;font-size:12px;color:#c8d8ec;margin:4px 0'>"
                            f"{dork}</div>",
                            unsafe_allow_html=True
                        )
                    with col_copy:
                        ddg_url = f"https://duckduckgo.com/?q={quote(dork)}"
                        st.markdown(
                            f"<a href='{ddg_url}' target='_blank'>"
                            f"<button style='background:#0d2a4a;border:1px solid #00b4ff;"
                            f"color:#00b4ff;border-radius:6px;padding:4px 10px;cursor:pointer;"
                            f"font-size:11px;margin-top:6px'>🔗 Run</button></a>",
                            unsafe_allow_html=True
                        )

        # Live execution
        if execute_dorks and dorks_flat:
            st.markdown("---")
            st.markdown(f"### ⚡ Live Execution — Top {max_execute} Dorks")
            to_exec = dorks_flat[:max_execute]
            all_results = {}
            exec_prog = st.progress(0)

            for idx, (cat, dork) in enumerate(to_exec):
                with st.spinner(f"🔍 Searching: `{dork[:60]}…`"):
                    results = search_dork(dork, num=5)
                all_results[(cat, dork)] = results
                exec_prog.progress(int((idx + 1) / len(to_exec) * 100))

            exec_prog.empty()
            total_hits = sum(len(r) for r in all_results.values())
            st.markdown(f"""
            <div class="metric-row">
              <div class="mcard"><div class="mcard-val">{len(to_exec)}</div><div class="mcard-lbl">Executed</div></div>
              <div class="mcard" style="border-color:#ef4444"><div class="mcard-val" style="color:#ef4444">{total_hits}</div><div class="mcard-lbl">Results Found</div></div>
            </div>
            """, unsafe_allow_html=True)

            for (cat, dork), results in all_results.items():
                if results:
                    with st.expander(f"🎯 [{cat}] `{dork[:70]}` — {len(results)} hits"):
                        for r in results:
                            st.markdown(
                                f"<div class='finding-card'>"
                                f"<div style='font-weight:600;color:#c8d8ec;font-size:13px'>{r['title']}</div>"
                                f"<div style='font-family:monospace;font-size:11px;color:#60a5fa;margin:3px 0'>{r['url']}</div>"
                                f"<div style='font-size:12px;color:#64748b'>{r['snippet']}</div>"
                                f"</div>",
                                unsafe_allow_html=True
                            )


# ══════════════════════════════════════════════════════
#  TAB 7 — DOMAIN & IP INTELLIGENCE
# ══════════════════════════════════════════════════════
with tab_domain:
    st.markdown("### 🔍 Domain & IP Intelligence")
    st.markdown(
        "Full passive recon: WHOIS · DNS records · Subdomain enumeration · "
        "IP geolocation & open ports · Certificate transparency · Tech fingerprinting · Wayback Machine"
    )

    di_c1, di_c2 = st.columns([4, 1])
    with di_c1:
        di_target = st.text_input(
            "di_t", label_visibility="collapsed",
            placeholder="domain.com · IP address · subdomain.example.com",
            key="di_input"
        )
    with di_c2:
        di_btn = st.button("🔍 ANALYZE", type="primary", use_container_width=True, key="di_analyze_btn")

    # Module checkboxes
    dc1, dc2, dc3, dc4 = st.columns(4)
    do_whois   = dc1.checkbox("WHOIS",          True,  key="do_whois")
    do_dns     = dc2.checkbox("DNS Records",    True,  key="do_dns")
    do_subs    = dc3.checkbox("Subdomains",     True,  key="do_subs")
    do_ip      = dc4.checkbox("IP Intel",       True,  key="do_ip")
    dc5, dc6, dc7, dc8 = st.columns(4)
    do_certs   = dc5.checkbox("Certificates",  True,  key="do_certs")
    do_tech    = dc6.checkbox("Tech Stack",    True,  key="do_tech")
    do_wayback = dc7.checkbox("Wayback",       True,  key="do_wayback")
    dc9, dc10, dc11, dc12 = st.columns(4)
    do_robots  = dc9.checkbox("Robots & Sitemap",   True,  key="do_robots")
    do_social  = dc10.checkbox("Social Media Links", True,  key="do_social")
    do_audit   = dc11.checkbox("Security Audit",     True,  key="do_audit")
    do_asn     = dc12.checkbox("ASN / BGP",          True,  key="do_asn")

    if di_btn and di_target:
        raw_target = di_target.strip()
        domain_clean = raw_target.replace("https://","").replace("http://","").split("/")[0]

        # ── WHOIS ─────────────────────────────────────────────────────────────
        if do_whois:
            st.markdown("---")
            st.markdown("#### 🌐 WHOIS / Registration Data")
            with st.spinner("Querying RDAP / WHOIS…"):
                w = whois_lookup(domain_clean)

            if w.get("parsed"):
                p = w["parsed"]
                col_w1, col_w2, col_w3 = st.columns(3)
                col_w1.metric("Registrar",  p.get("registrar","?")[:30] or "?")
                col_w2.metric("Created",    str(p.get("created","?"))[:10])
                col_w3.metric("Expires",    str(p.get("expires","?"))[:10])
                st.markdown(
                    f"<div class='finding-card'>"
                    f"<div style='font-size:11px;color:#00b4ff;font-weight:700'>SOURCE: {w.get('source','?')}</div>"
                    f"<div style='font-size:12px;color:#94a3b8;margin-top:6px'>"
                    f"<b>Nameservers:</b> {', '.join(p.get('nameservers',[])[:4]) or 'N/A'}<br>"
                    f"<b>Status:</b> {', '.join(p.get('status',[])[:3]) or 'N/A'}<br>"
                    f"<b>DNSSEC:</b> {'✅ Enabled' if p.get('dnssec') else '❌ Disabled'}"
                    f"</div></div>",
                    unsafe_allow_html=True
                )
                if p.get("registrant") and p["registrant"].get("name"):
                    st.info(f"👤 Registrant: {p['registrant'].get('name','?')} "
                            f"| {p['registrant'].get('email','[redacted]')}")
                with st.expander("📄 Raw WHOIS Data"):
                    st.code(w.get("raw", "")[:3000], language=None)
            elif w.get("error"):
                st.warning(f"⚠️ WHOIS: {w['error']}")

        # ── DNS Records ───────────────────────────────────────────────────────
        if do_dns:
            st.markdown("---")
            st.markdown("#### 🗂️ DNS Records")
            with st.spinner("Resolving DNS via Google DoH + Cloudflare DoH…"):
                dns = dns_recon(domain_clean)

            if dns.get("records"):
                recs = dns["records"]
                dns_color_map = {
                    "A":"#22c55e","AAAA":"#3b82f6","MX":"#f97316","NS":"#a78bfa",
                    "TXT":"#fbbf24","CNAME":"#06b6d4","SOA":"#64748b",
                    "CAA":"#ec4899","SRV":"#84cc16","PTR":"#78716c",
                }
                html_parts = []
                for rtype, vals in sorted(recs.items()):
                    clr = dns_color_map.get(rtype, "#c8d8ec")
                    for v in vals[:5]:
                        html_parts.append(
                            f"<div style='display:flex;gap:10px;padding:5px 0;"
                            f"border-bottom:1px solid #0d2a4a;font-family:monospace;font-size:12px'>"
                            f"<span style='color:{clr};min-width:60px;font-weight:700'>{rtype}</span>"
                            f"<span style='color:#c8d8ec'>{v}</span></div>"
                        )
                st.markdown(
                    f"<div style='background:#080f1e;border:1px solid #0d2a4a;"
                    f"border-radius:10px;padding:12px'>{''.join(html_parts)}</div>",
                    unsafe_allow_html=True
                )
                spf_list  = dns.get("spf", [])
                dmarc_list = dns.get("dmarc", [])
                if spf_list or dmarc_list:
                    st.markdown("**📧 Email Security:**")
                    if spf_list:
                        st.success(f"✅ SPF: `{spf_list[0][:100]}`")
                    else:
                        st.error("❌ No SPF record — spoofing possible")
                    if dmarc_list:
                        st.success(f"✅ DMARC: `{dmarc_list[0][:100]}`")
                    else:
                        st.error("❌ No DMARC policy — phishing risk")

        # ── Subdomains ────────────────────────────────────────────────────────
        if do_subs:
            st.markdown("---")
            st.markdown("#### 🌿 Subdomain Enumeration")
            with st.spinner("Querying crt.sh · HackerTarget · RapidDNS · CommonCrawl…"):
                subs = subdomain_enum(domain_clean)

            live_subs  = [s for s in subs["subdomains"] if s["live"]]
            dead_subs  = [s for s in subs["subdomains"] if not s["live"]]

            st.markdown(f"""
            <div class="metric-row">
              <div class="mcard"><div class="mcard-val">{subs['total_found']}</div><div class="mcard-lbl">Discovered</div></div>
              <div class="mcard" style="border-color:#22c55e"><div class="mcard-val" style="color:#22c55e">{subs['live_count']}</div><div class="mcard-lbl">Live</div></div>
              <div class="mcard" style="border-color:#6b7280"><div class="mcard-val" style="color:#6b7280">{len(dead_subs)}</div><div class="mcard-lbl">Dead</div></div>
            </div>
            """, unsafe_allow_html=True)

            if live_subs:
                with st.expander(f"✅ {len(live_subs)} Live Subdomains", expanded=True):
                    sub_rows = ""
                    for s in live_subs[:50]:
                        sub_rows += (
                            f"<div style='display:flex;justify-content:space-between;"
                            f"padding:5px 0;border-bottom:1px solid #0d2a4a;"
                            f"font-family:monospace;font-size:12px'>"
                            f"<span style='color:#22c55e'>● {s['subdomain']}</span>"
                            f"<span style='color:#3a6a9a'>{s['ip'] or ''}</span>"
                            f"</div>"
                        )
                    st.markdown(
                        f"<div style='background:#080f1e;border:1px solid #0d2a4a;"
                        f"border-radius:10px;padding:12px;max-height:300px;overflow-y:auto'>"
                        f"{sub_rows}</div>",
                        unsafe_allow_html=True
                    )
                    sub_dl = "\n".join(s["subdomain"] for s in live_subs)
                    st.download_button("📥 Download Live Subdomains", sub_dl,
                                       f"subdomains_{domain_clean}.txt", "text/plain")
            else:
                st.info("No live subdomains found.")

        # ── IP Intelligence ───────────────────────────────────────────────────
        if do_ip:
            st.markdown("---")
            st.markdown("#### 🌍 IP Intelligence")
            with st.spinner("ip-api.com · Shodan InternetDB · GreyNoise Community…"):
                ip_data = ip_intelligence(domain_clean)

            geo = ip_data.get("geo", {})
            shodan_d = ip_data.get("shodan", {})
            gn = ip_data.get("greynoise", {})

            ip_c1, ip_c2, ip_c3 = st.columns(3)
            ip_c1.metric("Resolved IP",  ip_data.get("ip","?"))
            ip_c2.metric("Country",      f"{geo.get('country','?')} ({geo.get('country_code','?')})")
            ip_c3.metric("ISP / Org",    (geo.get("isp","?") or "?")[:25])

            col_geo, col_threat = st.columns(2)
            with col_geo:
                st.markdown(
                    f"<div class='finding-card'>"
                    f"<div style='color:#00b4ff;font-weight:700;font-size:12px;margin-bottom:8px'>📍 GEOLOCATION</div>"
                    f"<div style='font-size:12px;color:#94a3b8;line-height:1.8'>"
                    f"<b>City:</b> {geo.get('city','?')}, {geo.get('region','?')}<br>"
                    f"<b>ZIP:</b> {geo.get('zip','?')}<br>"
                    f"<b>Timezone:</b> {geo.get('timezone','?')}<br>"
                    f"<b>ASN:</b> {geo.get('asn','?')}<br>"
                    f"<b>Lat/Lon:</b> {geo.get('lat','?')}, {geo.get('lon','?')}<br>"
                    f"<b>Proxy/VPN:</b> {'🚨 YES' if geo.get('proxy') else '✅ No'} | "
                    f"<b>Hosting:</b> {'🏢 YES' if geo.get('hosting') else '✅ No'}"
                    f"</div></div>",
                    unsafe_allow_html=True
                )
            with col_threat:
                if shodan_d:
                    ports_str = ", ".join(str(p) for p in shodan_d.get("open_ports",[])[:15]) or "None"
                    vulns_str = ", ".join(shodan_d.get("vulns",[])[:5]) or "None"
                    tags_str  = ", ".join(shodan_d.get("tags",[])[:5]) or "None"
                    st.markdown(
                        f"<div class='finding-card' style='border-left-color:#f97316'>"
                        f"<div style='color:#f97316;font-weight:700;font-size:12px;margin-bottom:8px'>⚡ SHODAN INTERNETDB</div>"
                        f"<div style='font-size:12px;color:#94a3b8;line-height:1.8'>"
                        f"<b>Open Ports:</b> {ports_str}<br>"
                        f"<b>CVEs:</b> <span style='color:{'#ef4444' if vulns_str != 'None' else '#22c55e'}'>{vulns_str}</span><br>"
                        f"<b>Tags:</b> {tags_str}"
                        f"</div></div>",
                        unsafe_allow_html=True
                    )
                if gn:
                    gn_cls = gn.get("classification","unknown")
                    gn_clr = ("#ef4444" if gn_cls=="malicious" else
                               "#f97316" if gn.get("noise") else "#22c55e")
                    st.markdown(
                        f"<div class='finding-card' style='border-left-color:{gn_clr}'>"
                        f"<div style='color:{gn_clr};font-weight:700;font-size:12px'>🌫️ GREYNOISE</div>"
                        f"<div style='font-size:12px;color:#94a3b8;margin-top:6px'>"
                        f"Noise: {'🔴 Yes' if gn.get('noise') else '✅ No'} | "
                        f"RIOT: {'✅ Known Good' if gn.get('riot') else '❓ Unknown'}<br>"
                        f"Classification: <b style='color:{gn_clr}'>{gn_cls.upper()}</b><br>"
                        f"{gn.get('name','') or ''}"
                        f"</div></div>",
                        unsafe_allow_html=True
                    )

            if ip_data.get("risk_flags"):
                for flag in ip_data["risk_flags"]:
                    st.warning(f"⚠️ {flag}")

        # ── Certificate Transparency ──────────────────────────────────────────
        if do_certs:
            st.markdown("---")
            st.markdown("#### 🔒 Certificate Transparency Logs")
            with st.spinner("Searching crt.sh CT logs…"):
                ct = cert_transparency(domain_clean)

            ct_c1, ct_c2, ct_c3 = st.columns(3)
            ct_c1.metric("Total Certs",    ct.get("total_certs", 0))
            ct_c2.metric("Wildcard Certs", ct.get("wildcard_certs", 0))
            ct_c3.metric("Issuers",        len(ct.get("top_issuers", {})))

            if ct.get("top_issuers"):
                iss_html = ""
                for iss, cnt in ct["top_issuers"].items():
                    iss_html += (
                        f"<div style='display:flex;justify-content:space-between;"
                        f"padding:4px 0;border-bottom:1px solid #0d2a4a;font-size:12px'>"
                        f"<span style='color:#a78bfa'>{iss[:50]}</span>"
                        f"<span style='color:#00b4ff'>{cnt} cert(s)</span>"
                        f"</div>"
                    )
                st.markdown(
                    f"<div class='finding-card'><div style='color:#a78bfa;font-weight:700;font-size:12px;margin-bottom:8px'>"
                    f"🏛️ TOP CERTIFICATE ISSUERS</div>{iss_html}</div>",
                    unsafe_allow_html=True
                )

            if ct.get("certificates"):
                with st.expander(f"📜 View {min(len(ct['certificates']),60)} Certificates"):
                    for c in ct["certificates"][:30]:
                        doms = ", ".join(c["domains"][:4])
                        st.markdown(
                            f"<div style='padding:5px 0;border-bottom:1px solid #0d2a4a;"
                            f"font-family:monospace;font-size:11px'>"
                            f"<span style='color:#22c55e'>ID:{c['id']}</span> · "
                            f"<span style='color:#3a6a9a'>{c['issuer'][:40]}</span> · "
                            f"<span style='color:#c8d8ec'>{doms}</span> · "
                            f"<span style='color:#64748b'>{str(c['not_before'])[:10]} – {str(c['not_after'])[:10]}</span>"
                            f"</div>",
                            unsafe_allow_html=True
                        )

        # ── Technology Fingerprinting ─────────────────────────────────────────
        if do_tech:
            st.markdown("---")
            st.markdown("#### 🛠️ Technology Fingerprinting")
            with st.spinner("Fingerprinting HTTP headers + HTML patterns…"):
                tf = tech_fingerprint(domain_clean)

            if tf.get("error"):
                st.error(f"Tech fingerprint error: {tf['error']}")
            else:
                tf_c1, tf_c2, tf_c3 = st.columns(3)
                tf_c1.metric("Tech Detected", len(tf.get("technologies",[])))
                tf_c2.metric("Security Grade", tf.get("security",{}).get("grade","?"))
                tf_c3.metric("External Links", tf.get("external_links_count",0))

                if tf.get("title"):
                    st.info(f"📄 Title: **{tf['title']}**")
                if tf.get("description"):
                    st.caption(f"📝 {tf['description'][:200]}")

                techs = tf.get("technologies", [])
                if techs:
                    cat_groups = {}
                    for t in techs:
                        cat_groups.setdefault(t["category"], []).append(t)

                    tech_html = ""
                    for cat, items in cat_groups.items():
                        tech_html += f"<div style='font-size:11px;color:#3a6a9a;text-transform:uppercase;margin:8px 0 4px'>{cat}</div>"
                        for item in items:
                            conf_clr = "#22c55e" if item["confidence"]=="High" else "#f97316"
                            tech_html += (
                                f"<span style='background:rgba(0,180,255,0.08);border:1px solid rgba(0,180,255,0.2);"
                                f"border-radius:6px;padding:2px 10px;margin:2px;display:inline-block;"
                                f"font-size:12px;color:#c8d8ec'>{item['name']} "
                                f"<span style='color:{conf_clr};font-size:10px'>●</span></span>"
                            )
                    st.markdown(
                        f"<div style='background:#080f1e;border:1px solid #0d2a4a;"
                        f"border-radius:10px;padding:12px'>{tech_html}</div>",
                        unsafe_allow_html=True
                    )

                sec = tf.get("security", {})
                if sec:
                    grade = sec.get("grade","?")
                    grade_clr = ("#22c55e" if grade=="A" else "#f97316" if grade=="B"
                                 else "#eab308" if grade=="C" else "#ef4444")
                    sec_html = f"<div style='font-size:11px;color:#3a6a9a;margin-bottom:8px'>SECURITY HEADERS — Grade: <b style='color:{grade_clr};font-size:18px'>{grade}</b> ({sec.get('score','?')})</div>"
                    for h in sec.get("present", {}):
                        sec_html += f"<div style='color:#22c55e;font-size:12px;font-family:monospace'>✅ {h}</div>"
                    for h in sec.get("missing", []):
                        sec_html += f"<div style='color:#ef4444;font-size:12px;font-family:monospace'>❌ {h} (MISSING)</div>"
                    st.markdown(
                        f"<div class='finding-card' style='border-left-color:{grade_clr}'>{sec_html}</div>",
                        unsafe_allow_html=True
                    )

        # ── Wayback Machine ───────────────────────────────────────────────────
        if do_wayback:
            st.markdown("---")
            st.markdown("#### 🕰️ Wayback Machine — Historical Archive")
            with st.spinner("Querying CDX API…"):
                wb = wayback_lookup(domain_clean)

            if wb.get("total_snapshots", 0) > 0:
                s = wb["summary"]
                wb_c1, wb_c2, wb_c3, wb_c4 = st.columns(4)
                wb_c1.metric("Total Snapshots", wb["total_snapshots"])
                wb_c2.metric("Year Range",       s.get("year_range","?"))
                wb_c3.metric("First Seen",        str(s.get("first_seen","?"))[:10])
                wb_c4.metric("Last Seen",          str(s.get("last_seen","?"))[:10])

                # Year chart (bar-style via markdown)
                by_year = s.get("by_year", {})
                if by_year:
                    max_v = max(by_year.values()) if by_year else 1
                    chart_html = "<div style='display:flex;align-items:flex-end;gap:4px;height:80px;margin:12px 0'>"
                    for yr, cnt in sorted(by_year.items()):
                        bar_h = max(4, int(cnt / max_v * 70))
                        chart_html += (
                            f"<div style='display:flex;flex-direction:column;align-items:center;flex:1'>"
                            f"<div style='background:#00b4ff;border-radius:3px 3px 0 0;width:100%;height:{bar_h}px;"
                            f"opacity:0.7' title='{yr}: {cnt}'></div>"
                            f"<div style='font-size:9px;color:#3a6a9a;margin-top:2px;transform:rotate(-45deg)"
                            f";transform-origin:top left'>{yr[2:]}</div></div>"
                        )
                    chart_html += "</div>"
                    st.markdown(
                        f"<div style='background:#080f1e;border:1px solid #0d2a4a;border-radius:10px;padding:12px'>"
                        f"<div style='font-size:11px;color:#3a6a9a;margin-bottom:4px'>SNAPSHOTS PER YEAR</div>"
                        f"{chart_html}</div>",
                        unsafe_allow_html=True
                    )

                if wb.get("closest"):
                    cl = wb["closest"]
                    st.markdown(
                        f"<a href='{cl.get('url','')}' target='_blank'>"
                        f"<div class='finding-card' style='cursor:pointer'>"
                        f"<div style='color:#00b4ff;font-weight:700'>🔗 Most Recent Snapshot</div>"
                        f"<div style='font-family:monospace;font-size:12px;color:#60a5fa;margin-top:4px'>"
                        f"{cl.get('url','')[:80]}</div>"
                        f"<div style='font-size:11px;color:#3a6a9a'>Timestamp: {cl.get('timestamp')} | "
                        f"HTTP {cl.get('status')}</div>"
                        f"</div></a>",
                        unsafe_allow_html=True
                    )

                with st.expander(f"📅 View {min(len(wb['snapshots']),50)} Snapshots"):
                    for snap in wb["snapshots"][:30]:
                        status_clr = "#22c55e" if snap["status"]=="200" else "#ef4444"
                        st.markdown(
                            f"<div style='padding:4px 0;border-bottom:1px solid #0d2a4a;"
                            f"font-family:monospace;font-size:11px;display:flex;justify-content:space-between'>"
                            f"<a href='{snap['wayback_url']}' target='_blank' "
                            f"style='color:#60a5fa'>{snap['formatted']}</a>"
                            f"<span style='color:{status_clr}'>HTTP {snap['status']}</span>"
                            f"<span style='color:#3a6a9a'>{snap['mime'][:25]}</span>"
                            f"</div>",
                            unsafe_allow_html=True
                        )
            else:
                st.info(f"No Wayback Machine snapshots found for `{domain_clean}`.")

        # ── Robots.txt & Sitemap ──────────────────────────────────────────────
        if do_robots:
            st.markdown("---")
            st.markdown("#### 🤖 Robots.txt & Sitemap Analysis")
            with st.spinner("Fetching robots.txt and sitemap…"):
                rb = robots_and_sitemap(domain_clean)

            r_c1, r_c2, r_c3 = st.columns(3)
            r_c1.metric("Disallowed Paths",  len(rb.get("disallowed", [])))
            r_c2.metric("Sitemap URLs",      rb.get("sitemap_page_count", 0))
            r_c3.metric("User Agents",       len(rb.get("user_agents", [])))

            sensitive = rb.get("sensitive_paths", [])
            if sensitive:
                st.error(f"🚨 {len(sensitive)} sensitive path(s) exposed in robots.txt!")
                sens_html = ""
                for sp in sensitive[:20]:
                    sens_html += (
                        f"<div style='padding:4px 0;border-bottom:1px solid #2d0a0a;"
                        f"font-family:monospace;font-size:12px;display:flex;gap:12px'>"
                        f"<span style='color:#ef4444;min-width:80px'>{sp['agent']}</span>"
                        f"<span style='color:#fca5a5'>Disallow: {sp['path']}</span></div>"
                    )
                st.markdown(
                    f"<div style='background:#1a0505;border:1px solid #ef4444;"
                    f"border-radius:10px;padding:12px'>{sens_html}</div>",
                    unsafe_allow_html=True
                )
            else:
                st.success("✅ No sensitive paths exposed in robots.txt")

            if rb.get("disallowed"):
                with st.expander(f"🚫 All Disallowed Paths ({len(rb['disallowed'])})"):
                    dis_html = ""
                    for d in rb["disallowed"][:40]:
                        dis_html += (
                            f"<div style='padding:3px 0;border-bottom:1px solid #0d2a4a;"
                            f"font-family:monospace;font-size:12px;color:#94a3b8'>"
                            f"<span style='color:#a78bfa;margin-right:12px'>{d['agent']}</span>"
                            f"Disallow: {d['path']}</div>"
                        )
                    st.markdown(
                        f"<div style='background:#080f1e;border:1px solid #0d2a4a;"
                        f"border-radius:8px;padding:10px'>{dis_html}</div>",
                        unsafe_allow_html=True
                    )

            if rb.get("sitemaps"):
                st.markdown("**🗺️ Sitemaps Found:**")
                for sm in rb["sitemaps"][:5]:
                    st.markdown(
                        f"<a href='{sm}' target='_blank' style='color:#60a5fa;"
                        f"font-family:monospace;font-size:12px'>{sm}</a>",
                        unsafe_allow_html=True
                    )

            if rb.get("sitemap_urls"):
                with st.expander(f"📄 Sitemap Pages ({rb['sitemap_page_count']} total)"):
                    for url in rb["sitemap_urls"][:40]:
                        st.markdown(
                            f"<div style='font-family:monospace;font-size:11px;"
                            f"color:#94a3b8;padding:2px 0'>{url}</div>",
                            unsafe_allow_html=True
                        )

        # ── Social Media Links ────────────────────────────────────────────────
        if do_social:
            st.markdown("---")
            st.markdown("#### 📱 Social Media Profile Discovery")
            with st.spinner("Crawling homepage, contact, about pages for social links…"):
                sm_data = social_media_from_domain(domain_clean)

            profiles = sm_data.get("social_profiles", {})
            sm_c1, sm_c2, sm_c3 = st.columns(3)
            sm_c1.metric("Platforms Found",   len(profiles))
            sm_c2.metric("Total Profiles",    sm_data.get("total_found", 0))
            sm_c3.metric("Pages Crawled",     len(sm_data.get("pages_crawled", [])))

            if profiles:
                platform_colors = {
                    "Twitter/X": "#1DA1F2", "LinkedIn": "#0A66C2",
                    "Facebook": "#1877F2",  "Instagram": "#E4405F",
                    "GitHub": "#c8d8ec",    "YouTube": "#FF0000",
                    "TikTok": "#69C9D0",    "Telegram": "#26A5E4",
                    "Discord": "#5865F2",   "Pinterest": "#BD081C",
                }
                for platform, links in profiles.items():
                    clr = platform_colors.get(platform, "#00b4ff")
                    links_html = ""
                    for link in links[:4]:
                        links_html += (
                            f"<a href='{link['url']}' target='_blank' "
                            f"style='color:{clr};font-family:monospace;font-size:12px;"
                            f"display:block;margin:2px 0'>@{link['handle']} → {link['url'][:60]}</a>"
                        )
                    st.markdown(
                        f"<div class='finding-card' style='border-left-color:{clr}'>"
                        f"<div style='color:{clr};font-weight:700;font-size:13px'>{platform}</div>"
                        f"<div style='margin-top:6px'>{links_html}</div>"
                        f"</div>",
                        unsafe_allow_html=True
                    )
            else:
                st.info("No social media profiles found in crawled pages.")

        # ── Security Audit ────────────────────────────────────────────────────
        if do_audit:
            st.markdown("---")
            st.markdown("#### 🔒 Security Header Audit")
            with st.spinner("Running security audit — headers, HTTPS, HSTS preload, cookies…"):
                audit = security_audit(domain_clean)

            grade = audit.get("grade", "?")
            score = audit.get("score", 0)
            max_s = audit.get("max_score", 100)
            grade_clr = (
                "#22c55e" if grade in ("A+","A") else
                "#84cc16" if grade == "B" else
                "#eab308" if grade == "C" else
                "#f97316" if grade == "D" else "#ef4444"
            )
            st.markdown(
                f"<div style='background:{grade_clr}18;border:2px solid {grade_clr};"
                f"border-radius:12px;padding:20px;text-align:center;margin:12px 0'>"
                f"<div style='font-size:3rem;font-weight:700;color:{grade_clr};"
                f"font-family:\"Share Tech Mono\",monospace'>{grade}</div>"
                f"<div style='color:#94a3b8;margin-top:4px'>"
                f"Security Score: <b style='color:{grade_clr}'>{score}/{max_s}</b> · "
                f"HSTS Preload: {'✅' if audit.get('hsts_preload') else '❌'}"
                f"</div></div>",
                unsafe_allow_html=True
            )

            checks = audit.get("checks", [])
            if checks:
                passed = [c for c in checks if c["passed"]]
                failed = [c for c in checks if not c["passed"]]
                aud_c1, aud_c2 = st.columns(2)
                with aud_c1:
                    st.markdown("**✅ Passed**")
                    for c in passed:
                        st.markdown(
                            f"<div style='color:#22c55e;font-size:12px;font-family:monospace;"
                            f"padding:3px 0;border-bottom:1px solid #0d2a4a'>"
                            f"✅ {c['check']} (+{c['points']})</div>",
                            unsafe_allow_html=True
                        )
                with aud_c2:
                    st.markdown("**❌ Failed**")
                    for c in failed:
                        st.markdown(
                            f"<div style='color:#ef4444;font-size:12px;font-family:monospace;"
                            f"padding:3px 0;border-bottom:1px solid #0d2a4a'>"
                            f"❌ {c['check']}<br>"
                            f"<span style='color:#64748b;font-size:10px'>{c['detail'][:80]}</span></div>",
                            unsafe_allow_html=True
                        )

            cookies = audit.get("cookies", [])
            if cookies:
                with st.expander(f"🍪 Cookies ({len(cookies)})"):
                    for ck in cookies:
                        s_clr = "#22c55e" if ck["secure"] else "#ef4444"
                        h_clr = "#22c55e" if ck["httponly"] else "#ef4444"
                        st.markdown(
                            f"<div style='font-family:monospace;font-size:12px;padding:4px 0;"
                            f"border-bottom:1px solid #0d2a4a;color:#c8d8ec'>"
                            f"{ck['name']} · "
                            f"<span style='color:{s_clr}'>Secure={'✅' if ck['secure'] else '❌'}</span> · "
                            f"<span style='color:{h_clr}'>HttpOnly={'✅' if ck['httponly'] else '❌'}</span> · "
                            f"<span style='color:#94a3b8'>SameSite={ck['samesite']}</span>"
                            f"</div>",
                            unsafe_allow_html=True
                        )

        # ── ASN / BGP Reputation ──────────────────────────────────────────────
        if do_asn:
            st.markdown("---")
            st.markdown("#### 🌐 ASN / BGP Intelligence")
            with st.spinner("Querying BGPView · ipinfo.io…"):
                asn_data = asn_reputation(domain_clean)

            if asn_data.get("error"):
                st.warning(f"⚠️ {asn_data['error']}")
            else:
                asn_details = asn_data.get("asn_details", {})
                ipinfo      = asn_data.get("ipinfo", {})
                bgpv        = asn_data.get("bgpview", {})

                asn_c1, asn_c2, asn_c3 = st.columns(3)
                asn_c1.metric("IP",        asn_data.get("ip", "?"))
                asn_c2.metric("ASN",       asn_details.get("asn", ipinfo.get("asn","?")))
                asn_c3.metric("RIR",       asn_details.get("rir", "?"))

                if asn_details:
                    st.markdown(
                        f"<div class='finding-card'>"
                        f"<div style='color:#00b4ff;font-weight:700;font-size:12px;margin-bottom:8px'>"
                        f"🏢 ASN DETAILS — {asn_details.get('asn','?')}</div>"
                        f"<div style='font-size:12px;color:#94a3b8;line-height:1.9'>"
                        f"<b>Name:</b> {asn_details.get('name','?')}<br>"
                        f"<b>Description:</b> {asn_details.get('description','?')}<br>"
                        f"<b>Country:</b> {asn_details.get('country','?')}<br>"
                        f"<b>Website:</b> {asn_details.get('website','?')}<br>"
                        f"<b>Abuse Contact:</b> {', '.join(asn_details.get('abuse_email',[])[:2]) or 'N/A'}<br>"
                        f"<b>Allocated:</b> {asn_details.get('allocated','?')}<br>"
                        f"<b>IPv4 Prefixes:</b> {asn_details.get('prefixes_v4',0)}"
                        f"</div></div>",
                        unsafe_allow_html=True
                    )

                if bgpv and bgpv.get("asns"):
                    with st.expander("📡 BGP Prefix Details"):
                        for asn_entry in bgpv["asns"][:5]:
                            st.markdown(
                                f"<div style='font-family:monospace;font-size:12px;padding:4px 0;"
                                f"border-bottom:1px solid #0d2a4a;color:#c8d8ec'>"
                                f"<span style='color:#00b4ff'>{asn_entry['asn']}</span> · "
                                f"{asn_entry['name']} · "
                                f"<span style='color:#a78bfa'>{asn_entry['prefix']}</span> · "
                                f"<span style='color:#3a6a9a'>{asn_entry['country']} / {asn_entry['rir']}</span>"
                                f"</div>",
                                unsafe_allow_html=True
                            )

        # ── Zone Transfer Check ───────────────────────────────────────────────
        # Always run after DNS as it's a critical security check
        if do_dns:
            st.markdown("---")
            st.markdown("#### ⚡ DNS Zone Transfer Check (AXFR)")
            st.caption("Attempts AXFR against all nameservers. A successful transfer is a CRITICAL vulnerability.")
            with st.spinner("Attempting zone transfer against nameservers…"):
                zt = zone_transfer_check(domain_clean)

            if zt.get("vulnerable"):
                st.error("🚨 CRITICAL — Zone transfer allowed! ALL DNS records exposed.")
            else:
                st.success("✅ Zone transfer refused by all nameservers (secure)")

            if zt.get("nameservers"):
                st.markdown(f"**Nameservers tested:** `{'`, `'.join(zt['nameservers'][:4])}`")

            for attempt in zt.get("attempts", []):
                clr = "#ef4444" if "VULNERABLE" in attempt["status"] else \
                      "#22c55e" if "REFUSED" in attempt["status"] else "#eab308"
                st.markdown(
                    f"<div style='display:flex;justify-content:space-between;padding:5px 0;"
                    f"border-bottom:1px solid #0d2a4a;font-family:monospace;font-size:12px'>"
                    f"<span style='color:#94a3b8'>{attempt['nameserver']}</span>"
                    f"<span style='color:{clr}'>{attempt['status']}</span>"
                    f"</div>",
                    unsafe_allow_html=True
                )


# ══════════════════════════════════════════════════════
#  TAB 8 — IDENTITY OSINT
# ══════════════════════════════════════════════════════
with tab_identity:
    st.markdown("### 👤 Identity OSINT")
    st.markdown("Username hunt across **50+ platforms** · Email intelligence · Phone OSINT")

    id_sub = st.radio(
        "Module",
        ["👤 Username Hunt", "📧 Email OSINT", "📞 Phone Intelligence"],
        horizontal=True, key="id_sub"
    )

    # ── USERNAME HUNT ─────────────────────────────────────────────────────────
    if id_sub == "👤 Username Hunt":
        st.markdown("#### 👤 Username Hunt — 50+ Platforms")
        u_c1, u_c2 = st.columns([4, 1])
        with u_c1:
            uh_username = st.text_input(
                "uh_u", label_visibility="collapsed",
                placeholder="Enter username to hunt…", key="uh_input"
            )
        with u_c2:
            uh_btn = st.button("🎯 HUNT", type="primary", use_container_width=True)

        if uh_btn and uh_username:
            with st.status(f"🔍 Hunting `{uh_username}` across {len(__import__('surface_web').PLATFORMS)} platforms…",
                           expanded=True) as uh_status:
                result = username_hunt(uh_username)
                uh_status.update(
                    label=f"✅ Hunt complete — {result['found_count']} profiles found",
                    state="complete"
                )

            st.markdown(f"""
            <div class="metric-row">
              <div class="mcard" style="border-color:#22c55e"><div class="mcard-val" style="color:#22c55e">{result['found_count']}</div><div class="mcard-lbl">Found</div></div>
              <div class="mcard"><div class="mcard-val">{result['checked']}</div><div class="mcard-lbl">Platforms Checked</div></div>
              <div class="mcard" style="border-color:#ef4444"><div class="mcard-val" style="color:#ef4444">{result['checked']-result['found_count']}</div><div class="mcard-lbl">Not Found</div></div>
            </div>
            """, unsafe_allow_html=True)

            if result["found"]:
                st.markdown(f"#### ✅ {result['found_count']} Profiles Discovered")

                # Group by category
                dev_platforms   = {"GitHub","GitLab","Bitbucket","Replit","HuggingFace","DockerHub","npmjs","PyPI","CodePen","StackOverflow","Kaggle","Codeforces","Codewars","GeeksForGeeks","Leetcode","HackerOne","BugCrowd","Exploit-DB","Shodan","Tryhackme","HackTheBox"}
                social_platforms = {"Twitter/X","Instagram","TikTok","Reddit","YouTube","Pinterest","Tumblr","Medium","Dev.to","Vimeo","SoundCloud","Twitch","Snapchat","Spotify","VK","Quora","Mastodon","Flickr"}

                groups = {"🛠️ Developer / Security": [], "🌐 Social Media": [], "🔗 Other": []}
                for f in result["found"]:
                    if f["platform"] in dev_platforms:
                        groups["🛠️ Developer / Security"].append(f)
                    elif f["platform"] in social_platforms:
                        groups["🌐 Social Media"].append(f)
                    else:
                        groups["🔗 Other"].append(f)

                for group_name, items in groups.items():
                    if not items:
                        continue
                    with st.expander(f"{group_name} — {len(items)} found", expanded=True):
                        cols = st.columns(2)
                        for idx, f in enumerate(items):
                            with cols[idx % 2]:
                                st.markdown(
                                    f"<div class='finding-card'>"
                                    f"<div style='font-weight:700;color:#c8d8ec;font-size:13px'>✅ {f['platform']}</div>"
                                    f"<div style='font-family:monospace;font-size:11px;color:#60a5fa;margin-top:4px'>"
                                    f"<a href='{f['url']}' target='_blank' style='color:#60a5fa'>{f['url'][:55]}</a>"
                                    f"</div></div>",
                                    unsafe_allow_html=True
                                )

                # Download report
                report_lines = [f"# Username Hunt: {uh_username}\n",
                                 f"Checked: {result['checked']} platforms\n",
                                 f"Found: {result['found_count']}\n\n"]
                for f in result["found"]:
                    report_lines.append(f"[FOUND] {f['platform']}: {f['url']}")
                for f in result["not_found"][:10]:
                    report_lines.append(f"[NOT FOUND] {f['platform']}")
                st.download_button(
                    "📥 Download Username Report",
                    "\n".join(report_lines),
                    f"username_{uh_username}_{datetime.now().strftime('%Y%m%d')}.txt",
                    "text/plain"
                )
            else:
                st.info(f"No profiles found for `{uh_username}` — username may be private or unused.")

    # ── EMAIL OSINT ───────────────────────────────────────────────────────────
    elif id_sub == "📧 Email OSINT":
        st.markdown("#### 📧 Email Intelligence")
        em_c1, em_c2 = st.columns([4, 1])
        with em_c1:
            em_input = st.text_input(
                "em_i", label_visibility="collapsed",
                placeholder="target@domain.com", key="em_input"
            )
        with em_c2:
            em_btn = st.button("🔍 ANALYZE", type="primary", use_container_width=True, key="em_analyze_btn")

        if em_btn and em_input:
            with st.spinner("Analyzing email…"):
                em = email_osint(em_input.strip())

            if em.get("error"):
                st.error(f"❌ {em['error']}")
            else:
                em_c1, em_c2, em_c3 = st.columns(3)
                em_c1.metric("Format",       "✅ Valid" if em["valid_format"] else "❌ Invalid")
                em_c2.metric("Disposable",   "🚨 YES" if em.get("is_disposable") else "✅ No")
                em_c3.metric("Can Receive",  "✅ Yes" if em.get("can_receive_email") else "❌ No")

                # Domain info
                if em.get("domain_info"):
                    di = em["domain_info"]
                    st.markdown(
                        f"<div class='finding-card'>"
                        f"<div style='color:#00b4ff;font-weight:700;font-size:12px'>🌐 DOMAIN: {em['domain']}</div>"
                        f"<div style='font-size:12px;color:#94a3b8;margin-top:6px'>"
                        f"<b>Registrar:</b> {di.get('registrar','?')[:50]}<br>"
                        f"<b>Created:</b> {str(di.get('created','?'))[:10]}<br>"
                        f"<b>MX Records:</b> {', '.join(em.get('mx_records',[])[:2]) or 'None'}"
                        f"</div></div>",
                        unsafe_allow_html=True
                    )

                # Gravatar
                grav = em.get("gravatar", {})
                if grav.get("found"):
                    gr_c1, gr_c2 = st.columns([1, 3])
                    with gr_c1:
                        st.image(grav["avatar"], width=80)
                    with gr_c2:
                        st.markdown(
                            f"<div class='finding-card' style='border-left-color:#a78bfa'>"
                            f"<div style='color:#a78bfa;font-weight:700;font-size:12px'>🎭 GRAVATAR PROFILE FOUND</div>"
                            f"<div style='font-size:12px;color:#c8d8ec;margin-top:6px'>"
                            f"<b>Display Name:</b> {grav.get('display_name','?')}<br>"
                            f"<b>Username:</b> {grav.get('username','?')}<br>"
                            f"<b>Profile:</b> <a href='{grav.get('profile_url','')}' target='_blank' "
                            f"style='color:#60a5fa'>{grav.get('profile_url','?')[:50]}</a><br>"
                            f"{'<b>About:</b> ' + grav['about'][:100] if grav.get('about') else ''}"
                            f"</div></div>",
                            unsafe_allow_html=True
                        )
                else:
                    st.info(f"No Gravatar profile linked to this email.")

                # OSINT dorks
                st.markdown("#### 🔍 Recommended OSINT Dorks")
                for dork in em.get("osint_dorks", []):
                    ddg_url = f"https://duckduckgo.com/?q={quote(dork)}"
                    st.markdown(
                        f"<div style='display:flex;justify-content:space-between;align-items:center;"
                        f"background:#080f1e;border:1px solid #0d2a4a;border-radius:6px;"
                        f"padding:6px 12px;margin:3px 0'>"
                        f"<code style='color:#c8d8ec;font-size:12px'>{dork}</code>"
                        f"<a href='{ddg_url}' target='_blank' "
                        f"style='color:#00b4ff;font-size:11px;text-decoration:none'>▶ Run</a>"
                        f"</div>",
                        unsafe_allow_html=True
                    )

    # ── PHONE INTELLIGENCE ────────────────────────────────────────────────────
    else:
        st.markdown("#### 📞 Phone Number Intelligence")
        ph_c1, ph_c2 = st.columns([4, 1])
        with ph_c1:
            ph_input = st.text_input(
                "ph_i", label_visibility="collapsed",
                placeholder="+1 555 123 4567  or  919876543210",
                key="ph_input"
            )
        with ph_c2:
            ph_btn = st.button("🔍 ANALYZE", type="primary", use_container_width=True, key="ph_analyze_btn")

        if ph_btn and ph_input:
            with st.spinner("Analyzing phone number…"):
                ph = phone_intel(ph_input.strip())

            ph_c1, ph_c2, ph_c3 = st.columns(3)
            ph_c1.metric("Normalized",   ph.get("normalized","?"))
            ph_c2.metric("Country",      ph.get("country","Unknown"))
            ph_c3.metric("Country Code", ph.get("country_code","?"))

            st.markdown(
                f"<div class='finding-card'>"
                f"<div style='color:#00b4ff;font-weight:700;font-size:12px'>📞 PHONE INTELLIGENCE</div>"
                f"<div style='font-size:12px;color:#94a3b8;margin-top:8px'>"
                f"<b>Original:</b> {ph['original']}<br>"
                f"<b>E.164:</b> {ph.get('normalized','?')}<br>"
                f"<b>Local Number:</b> {ph.get('local_number','?')}<br>"
                f"<b>Country:</b> {ph.get('country','?')} ({ph.get('country_code','?')})"
                f"</div></div>",
                unsafe_allow_html=True
            )

            st.markdown("#### 🔍 Public Lookup Links")
            for link in ph.get("osint_links", []):
                st.markdown(
                    f"<a href='{link}' target='_blank' style='color:#60a5fa;font-family:monospace;"
                    f"font-size:12px;display:block;margin:3px 0'>→ {link}</a>",
                    unsafe_allow_html=True
                )

            st.markdown("#### 🔍 OSINT Dorks")
            for dork in ph.get("osint_dorks", []):
                ddg_url = f"https://duckduckgo.com/?q={quote(dork)}"
                st.markdown(
                    f"<div style='display:flex;justify-content:space-between;align-items:center;"
                    f"background:#080f1e;border:1px solid #0d2a4a;border-radius:6px;"
                    f"padding:6px 12px;margin:3px 0'>"
                    f"<code style='color:#c8d8ec;font-size:12px'>{dork}</code>"
                    f"<a href='{ddg_url}' target='_blank' style='color:#00b4ff;font-size:11px;"
                    f"text-decoration:none'>▶ Run</a>"
                    f"</div>",
                    unsafe_allow_html=True
                )


# ══════════════════════════════════════════════════════
#  TAB 9 — THREAT INTELLIGENCE
# ══════════════════════════════════════════════════════
with tab_threat:
    st.markdown("### 🦠 Threat Intelligence — IOC Enrichment")
    st.markdown(
        "Multi-source IOC lookup: **AlienVault OTX · URLhaus · MalwareBazaar · ThreatFox**  \n"
        "Supports: IP Address · Domain · URL · Hash (MD5 / SHA1 / SHA256)"
    )

    ti_c1, ti_c2 = st.columns([4, 1])
    with ti_c1:
        ti_ioc = st.text_input(
            "ti_ioc", label_visibility="collapsed",
            placeholder="IOC: 1.2.3.4 · malicious.com · https://bad.site/payload · abc123hash…",
            key="ti_input"
        )
    with ti_c2:
        ti_btn = st.button("🔍 LOOKUP", type="primary", use_container_width=True)

    # IOC type quick examples
    with st.expander("💡 IOC Examples"):
        ec1, ec2, ec3, ec4 = st.columns(4)
        ec1.markdown("**🌐 Domains**\n- malware.cc\n- phishing-site.ru\n- c2-server.net")
        ec2.markdown("**🖥️ IPs**\n- 185.220.101.x\n- 45.142.212.x\n- 194.165.16.x")
        ec3.markdown("**🔗 URLs**\n- https://bad.ru/exe\n- http://phish.tk/login\n- …")
        ec4.markdown("**#️⃣ Hashes**\n- MD5: 32 chars\n- SHA1: 40 chars\n- SHA256: 64 chars")

    if ti_btn and ti_ioc:
        ioc = ti_ioc.strip()
        with st.status(f"🔬 Enriching IOC: `{ioc}`…", expanded=True) as ti_status:
            st.write("Querying AlienVault OTX…")
            st.write("Querying URLhaus · MalwareBazaar · ThreatFox…")
            ti_result = threat_intel_lookup(ioc)
            ti_status.update(
                label=f"✅ Enrichment complete — {ti_result['reputation']}",
                state="complete"
            )

        # Overall verdict
        rep = ti_result.get("reputation","UNKNOWN")
        rep_clr = ("#ef4444" if "MALICIOUS" in rep else
                   "#f97316" if "SUSPICIOUS" in rep else
                   "#22c55e" if "CLEAN" in rep else "#6b7280")
        risk_pct = ti_result.get("risk_score", 0)

        st.markdown(
            f"<div style='background:{rep_clr}18;border:2px solid {rep_clr};"
            f"border-radius:12px;padding:18px 24px;text-align:center;margin:12px 0'>"
            f"<div style='font-family:\"Share Tech Mono\",monospace;font-size:2rem;"
            f"color:{rep_clr};font-weight:700'>{rep}</div>"
            f"<div style='color:#94a3b8;margin-top:4px'>"
            f"IOC: <code style='color:#c8d8ec'>{ioc}</code> · "
            f"Type: <b style='color:#00b4ff'>{ti_result['type'].upper()}</b> · "
            f"Risk Score: <b style='color:{rep_clr}'>{risk_pct}/100</b></div>"
            f"</div>",
            unsafe_allow_html=True
        )

        # Detection breakdown
        dets = ti_result.get("detections", [])
        if dets:
            st.markdown(f"#### 🚨 {len(dets)} Source(s) Flagged")
            for det in dets:
                src_clr = "#ef4444" if det.get("detected") else "#22c55e"
                st.markdown(
                    f"<div class='finding-card' style='border-left-color:{src_clr}'>"
                    f"<div style='font-weight:700;color:{src_clr};font-size:13px'>"
                    f"{'🔴' if det['detected'] else '🟢'} {det['source']}</div>"
                    f"<div style='font-size:12px;color:#94a3b8;margin-top:4px'>{det.get('detail','')}</div>"
                    f"</div>",
                    unsafe_allow_html=True
                )

        # OTX details
        otx = ti_result.get("otx")
        if otx:
            with st.expander("🔵 AlienVault OTX Details"):
                st.metric("Threat Pulses", otx.get("pulse_count", 0))
                if otx.get("pulse_names"):
                    st.markdown("**Associated Pulse Names:**")
                    for name in otx["pulse_names"]:
                        st.markdown(f"- {name}")
                if otx.get("malware_families"):
                    st.markdown(f"**Malware Families:** {', '.join(otx['malware_families'])}")

        # URLhaus details
        uh = ti_result.get("urlhaus")
        if uh:
            with st.expander("🔗 URLhaus Details"):
                status_clr = "#ef4444" if uh.get("status")=="MALICIOUS" else "#22c55e"
                st.markdown(
                    f"<div class='finding-card' style='border-left-color:{status_clr}'>"
                    f"<b style='color:{status_clr}'>Status: {uh['status']}</b><br>"
                    f"<div style='font-size:12px;color:#94a3b8;margin-top:4px'>"
                    f"Threat Type: {uh.get('threat','N/A')}<br>"
                    f"Date Added: {uh.get('date_added','?')}<br>"
                    f"Tags: {', '.join(uh.get('tags',[]) or ['none'])}"
                    f"</div></div>",
                    unsafe_allow_html=True
                )

        # MalwareBazaar details
        mb = ti_result.get("malwarebazaar")
        if mb:
            with st.expander("💀 MalwareBazaar Details"):
                st.markdown(
                    f"<div class='finding-card' style='border-left-color:#ef4444'>"
                    f"<b style='color:#ef4444'>MALICIOUS SAMPLE</b><br>"
                    f"<div style='font-size:12px;color:#94a3b8;margin-top:6px;line-height:1.8'>"
                    f"<b>Filename:</b> {mb.get('file_name','?')}<br>"
                    f"<b>File Type:</b> {mb.get('file_type','?')}<br>"
                    f"<b>Signature:</b> {mb.get('signature','?')}<br>"
                    f"<b>First Seen:</b> {mb.get('first_seen','?')}<br>"
                    f"<b>Tags:</b> {', '.join(mb.get('tags',[]) or ['none'])}"
                    f"</div></div>",
                    unsafe_allow_html=True
                )

        # ThreatFox details
        tf_data = ti_result.get("threatfox")
        if tf_data:
            with st.expander(f"🕷️ ThreatFox — {len(tf_data)} match(es)"):
                for entry in tf_data:
                    st.markdown(
                        f"<div class='finding-card' style='border-left-color:#a855f7'>"
                        f"<div style='font-size:12px;color:#94a3b8;line-height:1.8'>"
                        f"<b>IOC:</b> <code style='color:#c8d8ec'>{entry.get('ioc','?')}</code><br>"
                        f"<b>Threat Type:</b> {entry.get('threat_type','?')}<br>"
                        f"<b>Malware:</b> {entry.get('malware','?')}<br>"
                        f"<b>First Seen:</b> {entry.get('first_seen','?')}<br>"
                        f"<b>Tags:</b> {', '.join(entry.get('tags',[]) or ['none'])}"
                        f"</div></div>",
                        unsafe_allow_html=True
                    )

        # No detections
        if not dets:
            st.success(f"✅ No threat intelligence matches found for `{ioc}` across all sources.")
            st.caption("This does not guarantee the IOC is safe — always verify with additional tools.")

        # Export
        ti_json = json.dumps({
            "ioc":        ioc,
            "type":       ti_result["type"],
            "reputation": ti_result["reputation"],
            "risk_score": ti_result["risk_score"],
            "detections": ti_result["detections"],
            "otx":        ti_result.get("otx"),
            "urlhaus":    ti_result.get("urlhaus"),
            "malwarebazaar": ti_result.get("malwarebazaar"),
            "threatfox":  ti_result.get("threatfox"),
            "timestamp":  datetime.now().isoformat(),
        }, indent=2)
        st.download_button(
            "📥 Export Threat Intel Report (JSON)", ti_json,
            f"threat_intel_{ioc.replace('/','-')}_{datetime.now().strftime('%Y%m%d')}.json",
            "application/json"
        )
