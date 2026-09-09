import time
from datetime import datetime
from pathlib import Path

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

from shadowtrust_engine import (
    ShadowTrustEngine,
    generate_synthetic_data,
    inject_attack
)

BACKEND_URL = "http://127.0.0.1:8000"


def process_event_through_backend(event):
    payload = {
        "identity": event.get("identity"),
        "resource": event.get("resource"),
        "action": event.get("action"),
        "timestamp": (
            event.get("timestamp").isoformat()
            if hasattr(event.get("timestamp"), "isoformat")
            else str(event.get("timestamp"))
        )
    }

    try:
        response = requests.post(
            f"{BACKEND_URL}/activity",
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="ShadowTrust",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# The landing surface uses Streamlit components so its controls can coexist
# with the input-gated trust engine below.
st.markdown(
    """
    <style>
    .stApp { background: #050914; color: #e8f1ff; }
    [data-testid="stHeader"] { background: transparent !important; border: none !important; box-shadow: none !important; }
    [data-testid="stToolbar"], .stDeployButton, [data-testid="stDecoration"] { display: none !important; }
    [data-testid="stAppViewContainer"], [data-testid="stMain"] { background: #050914; }
    .shadowtrust-streamlit { background: #050914; color: #e8f1ff; }
    .shadowtrust-streamlit > div:first-child { border-top: none !important; box-shadow: none !important; }
    .shadowtrust-shell { display: none !important; }
    .stApp::before {
        content: "";
        position: fixed;
        inset: 0;
        z-index: -1;
        background-image: linear-gradient(rgba(0, 217, 255, 0.035) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 217, 255, 0.035) 1px, transparent 1px);
        background-size: 70px 70px;
    }
    .logo { font-size: 32px; font-weight: 800; color: #ffffff; }
    .shadowtrust-streamlit .logo { font-size: 32px; font-weight: 800; color: #ffffff; }
    .shadowtrust-streamlit .logo-mark { color: #ffffff; filter: grayscale(1) brightness(2.2); }
    .shadowtrust-streamlit .top-brand { padding: 10px 20px 2px; font-size: 24px; font-weight: 800; letter-spacing: 1.5px; color: #ffffff; }
    .shadowtrust-streamlit .logo span, .shadowtrust-streamlit .hero-title span { color: #00d9ff; }
    .shadowtrust-streamlit .hero { padding: 12px 20px 8px; text-align: left; }
    .shadowtrust-streamlit .product-heading { margin: 14px 0 3px; color: #ffffff; font-size: clamp(22px, 2.5vw, 32px); font-weight: 800; letter-spacing: .04em; }
    .shadowtrust-streamlit .badge {
        display: inline-block;
        padding: 8px 15px;
        border: 1px solid rgba(0, 217, 255, 0.3);
        border-radius: 30px;
        color: #00d9ff;
        font-size: 12px;
        letter-spacing: 1px;
        background: rgba(0, 217, 255, 0.05);
    }
    .shadowtrust-streamlit .hero-title { font-size: clamp(38px, 4.5vw, 58px); font-weight: 800; line-height: 1.08; margin-top: 8px; margin-bottom: 8px; color: #ffffff; text-shadow: 0 0 18px rgba(255, 255, 255, 0.12); }
    .shadowtrust-streamlit .hero-title span {
        background: linear-gradient(90deg, #00eaff 0%, #35e78b 100%);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
        text-shadow: 0 0 18px rgba(0, 234, 255, 0.25);
    }
    .shadowtrust-streamlit .hero-text { color: #91a4bd; font-size: 15px; line-height: 1.5; max-width: 600px; margin: 8px 0 0; }
    .shadowtrust-streamlit .hero-text b { color: #e8f1ff; }
    .shadowtrust-streamlit .hero-grid { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.65fr); gap: 28px; align-items: center; }
    .shadowtrust-streamlit .card, .shadowtrust-streamlit .workflow {
        background: #0b1424;
        border: 1px solid #17283f;
        border-radius: 15px;
        padding: 20px;
        margin-bottom: 12px;
    }
    .shadowtrust-streamlit .card-title { font-size: 16px; font-weight: 700; color: #ffffff; }
    .shadowtrust-streamlit .card-text { color: #7e91aa; font-size: 14px; line-height: 1.6; }
    .shadowtrust-streamlit .trust-score { font-size: 55px; font-weight: 800; color: #00d9ff; }
    .shadowtrust-streamlit .security-panel { border-color: rgba(0, 217, 255, 0.28); box-shadow: 0 16px 40px rgba(0, 180, 255, 0.08); }
    .shadowtrust-streamlit .gauge { width: 150px; height: 150px; margin: 18px auto 12px; display: grid; place-items: center; border-radius: 50%; background: conic-gradient(#35e78b 0deg 331deg, #1c3047 331deg 360deg); box-shadow: 0 0 25px rgba(53, 231, 139, .15); }
    .shadowtrust-streamlit .gauge-center { width: 118px; height: 118px; display: grid; place-content: center; text-align: center; border-radius: 50%; background: #0b1424; }
    .shadowtrust-streamlit .gauge-score { color: #ffffff; font-size: 34px; font-weight: 800; line-height: 1; }
    .shadowtrust-streamlit .gauge-score small { color: #657a94; font-size: 14px; }
    .shadowtrust-streamlit .gauge-label { margin-top: 6px; color: #91a4bd; font-size: 11px; letter-spacing: .08em; text-transform: uppercase; }
    .shadowtrust-streamlit .panel-label { color: #657a94; font-size: 11px; letter-spacing: 1.5px; text-transform: uppercase; }
    .shadowtrust-streamlit .feature-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
    .shadowtrust-streamlit .feature-card { margin-bottom: 0; transition: transform .2s ease, border-color .2s ease; }
    .shadowtrust-streamlit .feature-card:hover { transform: translateY(-3px); border-color: rgba(0, 217, 255, 0.45); }
    .shadowtrust-streamlit .feature-icon { font-size: 24px; margin-bottom: 8px; }
    .shadowtrust-streamlit .normal { color: #35e78b; font-weight: 700; }
    .shadowtrust-streamlit .drifting { color: #ffad42; font-weight: 700; }
    .shadowtrust-streamlit .suspicious { color: #ff704d; font-weight: 700; }
    .shadowtrust-streamlit .highrisk { color: #ff4d5a; font-weight: 700; }
    .shadowtrust-streamlit .workflow-step { color: #00d9ff; font-weight: 700; font-size: 16px; }
    .shadowtrust-streamlit .workflow { padding: 26px; }
    .shadowtrust-streamlit .workflow-title { margin: 6px 0 4px; color: #ffffff; font-size: 28px; font-weight: 750; }
    .shadowtrust-streamlit .workflow-description { max-width: 720px; margin: 0 0 22px; color: #91a4bd; font-size: 14px; line-height: 1.55; }
    .shadowtrust-streamlit .workflow-guidelines { margin: 0 0 22px; padding: 16px 18px; border-left: 3px solid #00d9ff; border-radius: 0 10px 10px 0; background: rgba(0, 217, 255, .05); color: #aebed1; font-size: 13px; line-height: 1.75; }
    .shadowtrust-streamlit .workflow-guidelines b { color: #ffffff; }
    .shadowtrust-streamlit .workflow-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; }
    .shadowtrust-streamlit .workflow-card { min-height: 152px; padding: 15px; background: #0e1a2d; border: 1px solid #1c314d; border-radius: 11px; }
    .shadowtrust-streamlit .workflow-number { color: #00d9ff; font-family: monospace; font-size: 12px; letter-spacing: 1px; }
    .shadowtrust-streamlit .workflow-name { margin: 9px 0 6px; color: #ffffff; font-size: 14px; font-weight: 700; }
    .shadowtrust-streamlit .workflow-copy { margin: 0; color: #7e91aa; font-size: 12px; line-height: 1.5; }
    .shadowtrust-streamlit .workflow-card.shadow { border-color: rgba(167, 139, 250, .45); }
    .shadowtrust-streamlit .workflow-card.gate { border-color: rgba(255, 173, 66, .5); }
    .shadowtrust-streamlit .workflow-card.decision { border-color: rgba(53, 231, 139, .48); background: linear-gradient(145deg, #102b2c, #0b1424); }
    .shadowtrust-streamlit .workflow-card.explain { border-color: rgba(0, 217, 255, .45); }
    .shadowtrust-streamlit .footer { text-align: center; padding: 20px; color: #657a94; border-top: 1px solid #15243a; margin-top: 16px; }
    [data-testid="stMainBlockContainer"] { padding-top: 1rem; padding-bottom: 1rem; }
    [data-testid="stVerticalBlock"] { gap: 0.65rem; }
    @media (max-width: 1000px) { .shadowtrust-streamlit .workflow-grid, .ops-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
    @media (max-width: 800px) { .shadowtrust-streamlit .hero-grid { grid-template-columns: 1fr; } .shadowtrust-streamlit .feature-grid { grid-template-columns: 1fr 1fr; } }
    @media (max-width: 520px) {
        .shadowtrust-streamlit .feature-grid, .shadowtrust-streamlit .workflow-grid, .ops-grid { grid-template-columns: 1fr; }
        .shadowtrust-streamlit .hero { text-align: center; }
    }

    /* Live dashboard theme */
    [data-testid="stSidebar"] {
        background: #07101f;
        border-right: 1px solid #17283f;
    }

    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] .sidebar-brand { color: #ffffff; font-size: 22px; font-weight: 800; letter-spacing: .06em; }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] .sidebar-kicker { color: #00d9ff; font-family: monospace; font-size: 11px; letter-spacing: .12em; }
    [data-testid="stSidebar"] .nav-tree { display: grid; gap: 7px; margin: 6px 0 10px; }
    [data-testid="stSidebar"] .nav-item { display: flex; align-items: center; gap: 9px; padding: 9px 10px; border-radius: 8px; color: #91a4bd; font-size: 14px; }
    [data-testid="stSidebar"] .nav-item:first-child { background: rgba(0, 217, 255, .08); border: 1px solid rgba(0, 217, 255, .18); color: #00d9ff; }
    [data-testid="stSidebar"] .nav-arrow { color: #ffffff; font-family: monospace; font-size: 12px; font-weight: 800; letter-spacing: -2px; }
    [data-testid="stSidebarCollapsedControl"] button, [data-testid="stSidebar"] button[kind="header"] { color: #ffffff !important; background: #0d1525 !important; border: 1px solid rgba(255,255,255,.22) !important; }
    .notification-card { margin-top: 12px; padding: 14px; border: 1px solid rgba(0, 217, 255, .25); border-radius: 10px; background: #0b1424; }
    .notification-title { color: #ffffff; font-family: monospace; font-size: 12px; font-weight: 800; letter-spacing: .1em; }
    .notification-row { display: flex; justify-content: space-between; padding: 5px 0; color: #91a4bd; font-size: 12px; }
    .notification-row strong { color: #e8f1ff; }
    .notification-row .protected-text { color: #35e78b; }
    .ops-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 10px 0 28px; }
    .ops-card { min-height: 86px; padding: 14px; border: 1px solid #1d304a; border-radius: 10px; background: #0b1424; color: #dbeafe; font-size: 13px; font-weight: 650; }
    .ops-card span { display: block; margin-bottom: 8px; color: #00d9ff; font-family: monospace; font-size: 10px; letter-spacing: .1em; }

    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] label {
        color: #d9e8fa;
    }

    [data-testid="stMetric"] {
        background: #0b1424;
        border: 1px solid #17283f;
        border-radius: 13px;
        padding: 16px;
        box-shadow: 0 8px 24px rgba(0, 180, 255, 0.06);
    }

    [data-testid="stMetricLabel"] p {
        color: #91a4bd;
    }

    [data-testid="stMetricValue"] {
        color: #00d9ff;
    }

    .stButton > button {
        background: #0d1728;
        color: #d9e8fa;
        border: 1px solid #20334d;
        border-radius: 8px;
    }

    .stButton > button:hover {
        color: #00d9ff;
        border-color: #00d9ff;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #17283f;
        border-radius: 12px;
        overflow: hidden;
    }

    .stSelectbox div[data-baseweb="select"] > div,
    .stTextInput input {
        background: #0b1424;
        color: #e8f1ff;
        border-color: #20334d;
    }

    h1, h2, h3 {
        color: #e8f1ff;
    }

    h2 {
        font-size: 1.45rem;
        margin-top: 1rem;
    }

    h3 {
        font-size: 1.1rem;
    }

    [data-testid="stAlert"] {
        background: #0b1424;
        border-color: #20334d;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

nav1, nav2, nav3, nav4 = st.columns([3, 1, 1, 1])
with nav1:
    logo_path = Path(__file__).with_name("logo.png")
    if logo_path.exists():
        logo_col, name_col = st.columns([1, 5])
        with logo_col:
            st.image(str(logo_path), width=80)
        with name_col:
            st.markdown('<div class="logo">SHADOWTRUST</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="logo"><span class="logo-mark">🛡️</span> <span>SHADOWTRUST</span></div>', unsafe_allow_html=True)
with nav2:
    st.markdown('<a href="#features" style="color:#91a4bd;text-decoration:none;">Features</a>', unsafe_allow_html=True)
with nav3:
    st.markdown('<a href="#workflow" style="color:#91a4bd;text-decoration:none;">How It Works</a>', unsafe_allow_html=True)
with nav4:
    login_clicked = st.button("Login", key="landing_login")

if login_clicked:
    st.info("Login is available when identity authentication is connected.")

st.markdown(
    """
    <div class="shadowtrust-streamlit">
        <div class="hero hero-grid">
            <div>
                <div class="badge">● ADAPTIVE SECURITY SYSTEM</div>
                <div class="product-heading">ShadowTrust</div>
                <div class="hero-title">Trust Behavior. <span>Not Assumptions.</span></div>
                <p class="hero-text">Adaptive behavioral security for <b>Non-human identities.</b></p>
            </div>
            <div class="card security-panel">
                <div class="panel-label">Identity security <span class="normal" style="float:right">● LIVE</span></div>
                <div class="gauge"><div class="gauge-center"><div class="gauge-score">92<small>/100</small></div><div class="gauge-label">Trust score</div></div></div>
                <div class="card-text" style="text-align:center">svc-payment-prod</div>
                <div class="card-text" style="text-align:center;margin-top:8px"><span class="normal">● NORMAL</span> &nbsp; Baseline protected</div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

landing_col1, landing_col2, _ = st.columns([1, 1, 4])
with landing_col1:
    start_monitoring = st.button("Start monitoring", key="landing_start", icon=":material/play_arrow:", type="primary")
with landing_col2:
    view_dashboard = st.button("View dashboard", key="landing_dashboard", icon=":material/dashboard:")

if start_monitoring or view_dashboard:
    st.session_state["load_demo_from_landing"] = True

st.markdown('<p class="normal">● System Protected</p>', unsafe_allow_html=True)

st.markdown(
    """
    <div class="shadowtrust-streamlit">
        <div id="features"><h2>Core capabilities</h2></div>
        <div class="feature-grid">
            <div class="card feature-card"><div class="feature-icon">◈</div><div class="card-title">Behavioral detection</div><p class="card-text">Identify unusual changes in identity behavior before they become baseline.</p></div>
            <div class="card feature-card"><div class="feature-icon">◎</div><div class="card-title">Relationship graph</div><p class="card-text">Map identities, resources, and actions to surface risky connections.</p></div>
            <div class="card feature-card"><div class="feature-icon">✦</div><div class="card-title">Dynamic trust score</div><p class="card-text">Continuously calculate a trust score from observed activity.</p></div>
            <div class="card feature-card"><div class="feature-icon">◐</div><div class="card-title">Shadow profile</div><p class="card-text">Learn emerging behavior without changing the trusted baseline.</p></div>
            <div class="card feature-card"><div class="feature-icon">⟐</div><div class="card-title">Adaptation gate</div><p class="card-text">Promote only verified behavior into the trusted model.</p></div>
            <div class="card feature-card"><div class="feature-icon">↗</div><div class="card-title">Dual timeline</div><p class="card-text">Compare immediate activity with long-term trusted patterns.</p></div>
        </div>
        <section id="workflow" class="workflow">
            <div class="panel-label">ShadowTrust decision pipeline</div>
            <p class="workflow-description">Every new identity action is observed, compared against trusted history, and held outside the baseline until it earns trust. This protects your baseline from slow-burn and poisoning attacks.</p>
            <div class="workflow-guidelines"><b>How it works</b><br>Monitor NHI activities · compare current behavior with trusted behavior · detect unusual changes · assign a risk/trust score · keep new behavior in Shadow Profile · use the Adaptation Gate to allow or block baseline updates · generate alerts for suspicious activity · provide a clear reason for every decision · protect the trusted baseline from poisoning.</div>
            <div class="workflow-grid">
                <article class="workflow-card"><div class="workflow-number">01 / INPUT</div><div class="workflow-name">Activity arrives</div><p class="workflow-copy">An NHI performs an action in your environment.</p></article>
                <article class="workflow-card"><div class="workflow-number">02 / OBSERVE</div><div class="workflow-name">Feature extraction</div><p class="workflow-copy">Collect resource, action, time, frequency, and sequence signals.</p></article>
                <article class="workflow-card"><div class="workflow-number">03 / MAP</div><div class="workflow-name">Behavioral graph</div><p class="workflow-copy">Create or update identity-to-resource-to-action relationships.</p></article>
                <article class="workflow-card"><div class="workflow-number">04 / COMPARE</div><div class="workflow-name">Dual timeline</div><p class="workflow-copy">Compare recent activity with the stable, trusted timeline.</p></article>
                <article class="workflow-card"><div class="workflow-number">05 / CLASSIFY</div><div class="workflow-name">State detection</div><p class="workflow-copy"><span class="normal">NORMAL</span> · <span class="drifting">DRIFTING</span> · <span class="suspicious">SUSPICIOUS</span> · <span class="highrisk">HIGH-RISK</span></p></article>
                <article class="workflow-card shadow"><div class="workflow-number">06 / ISOLATE</div><div class="workflow-name">Shadow profile</div><p class="workflow-copy">Learn new behavior in isolation; never add it directly to the baseline.</p></article>
                <article class="workflow-card"><div class="workflow-number">07 / SCORE</div><div class="workflow-name">Trust credit score</div><p class="workflow-copy">Update the identity's dynamic trust and risk score.</p></article>
                <article class="workflow-card gate"><div class="workflow-number">08 / VERIFY</div><div class="workflow-name">Adaptation gate</div><p class="workflow-copy">Ask: is this behavior safe to promote into the trusted baseline?</p></article>
                <article class="workflow-card decision"><div class="workflow-number">09 / DECIDE</div><div class="workflow-name">Final decision</div><p class="workflow-copy"><span class="normal">ALLOW</span> updates stable baseline. <span class="highrisk">BLOCK</span> keeps behavior isolated.</p></article>
                <article class="workflow-card explain"><div class="workflow-number">10 / EXPLAIN</div><div class="workflow-name">Explanation system</div><p class="workflow-copy">Give analysts and users a clear reason for every decision.</p></article>
            </div>
        </section>
        <div class="footer"><span class="logo-mark">🛡️</span> ShadowTrust<br><small>Adaptive Behavioral Trust for Non-Human Identities</small></div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <style>
    * {
        box-sizing: border-box;
    }

    .stApp {
        background: #050914;
        color: #e8f1ff;
    }

    .shadowtrust-shell {
        width: 90%;
        max-width: 1200px;
        margin: 0 auto;
        font-family: 'Inter', sans-serif;
        background: #050914;
        color: #e8f1ff;
    }

    .network-bg {
        position: fixed;
        inset: 0;
        background-image: linear-gradient(rgba(0, 180, 255, 0.035) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 180, 255, 0.035) 1px, transparent 1px);
        background-size: 70px 70px;
        mask-image: linear-gradient(to bottom, black, transparent 90%);
        pointer-events: none;
        z-index: -1;
    }

    .navbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 22px;
        margin: 20px 0;
        background: rgba(10, 18, 35, 0.75);
        border: 1px solid rgba(0, 200, 255, 0.15);
        border-radius: 14px;
        backdrop-filter: blur(12px);
    }

    .logo {
        display: flex;
        align-items: center;
        gap: 10px;
        font-weight: 800;
        letter-spacing: 0.04em;
        font-size: 1.1rem;
        color: #ffffff;
    }

    .navbar nav {
        display: flex;
        align-items: center;
        gap: 30px;
    }

    .navbar nav a {
        color: #91a4bd;
        text-decoration: none;
        font-size: 0.9rem;
        opacity: 0.85;
    }

    .navbar nav a:hover {
        color: #00d9ff;
    }

    .login-btn, .primary-btn, .secondary-btn {
        border: none;
        border-radius: 12px;
        cursor: pointer;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }

    .login-btn {
        background: transparent;
        color: #00d9ff;
        padding: 9px 18px;
        border: 1px solid #00d9ff;
        border-radius: 7px;
    }

    .hero {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 70px;
    }

    .hero-content {
        max-width: 650px;
    }

    .badge {
        display: inline-block;
        padding: 8px 14px;
        margin-bottom: 25px;
        color: #00d9ff;
        border: 1px solid rgba(0, 217, 255, 0.3);
        background: rgba(0, 217, 255, 0.05);
        border-radius: 30px;
        font-size: 11px;
        letter-spacing: 1.5px;
    }

    .hero h1 {
        font-size: clamp(45px, 6vw, 78px);
        line-height: 1.05;
        letter-spacing: -3px;
    }

    .hero h1 span {
        color: #00d9ff;
    }

    .hero p {
        margin-top: 25px;
        max-width: 560px;
        color: #91a4bd;
        font-size: 18px;
        line-height: 1.7;
    }

    .hero p strong {
        color: #e8f1ff;
    }

    .hero-buttons {
        display: flex;
        gap: 15px;
        margin-top: 35px;
        flex-wrap: wrap;
    }

    .primary-btn {
        padding: 14px 22px;
        background: #00cfff;
        color: #021019;
        border: none;
        box-shadow: 0 0 25px rgba(0, 207, 255, 0.25);
    }

    .secondary-btn {
        padding: 14px 22px;
        background: #0d1728;
        color: #d9e8fa;
        border: 1px solid #20334d;
    }

    .secondary-btn:hover {
        border-color: #00d9ff;
    }

    .system-status {
        display: inline-flex;
        margin-top: 25px;
        color: #65e6a5;
        font-size: 13px;
    }

    .status-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        margin-right: 7px;
        border-radius: 50%;
        background: #35e78b;
        box-shadow: 0 0 10px #35e78b;
    }

    .security-card {
        width: 340px;
        padding: 28px;
        background: rgba(11, 21, 39, 0.85);
        border: 1px solid rgba(0, 217, 255, 0.2);
        border-radius: 18px;
        box-shadow: 0 0 50px rgba(0, 180, 255, 0.08);
        backdrop-filter: blur(15px);
    }

    .card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        color: #6f829b;
        font-size: 11px;
        letter-spacing: 1.5px;
    }

    .live {
        color: #35e78b;
    }

    .security-card h3 {
        margin-top: 30px;
        font-size: 20px;
    }

    .score {
        display: flex;
        align-items: end;
        margin-top: 30px;
        gap: 8px;
    }

    .score span {
        color: #91a4bd;
    }

    .score strong {
        margin-left: auto;
        font-size: 45px;
        color: #00d9ff;
    }

    .score small {
        color: #657a94;
    }

    .progress {
        width: 100%;
        height: 7px;
        margin-top: 12px;
        background: #18263b;
        border-radius: 10px;
        overflow: hidden;
    }

    .progress-bar {
        width: 92%;
        height: 100%;
        background: #00d9ff;
        border-radius: 10px;
        box-shadow: 0 0 12px rgba(0, 217, 255, 0.7);
    }

    .card-info {
        display: flex;
        justify-content: space-between;
        margin-top: 30px;
    }

    .card-info small {
        display: block;
        color: #657a94;
    }

    .normal {
        color: #35e78b;
    }

    section.section {
        width: 100%;
        margin: 40px auto 0;
    }

    .section-title {
        margin-bottom: 45px;
    }

    .section-title span {
        color: #00d9ff;
        font-size: 11px;
        letter-spacing: 2px;
    }

    .section-title h2 {
        margin-top: 10px;
        font-size: 34px;
    }

    .features {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 18px;
    }

    .feature-card {
        padding: 28px;
        background: #0b1424;
        border: 1px solid #17283f;
        border-radius: 14px;
        transition: 0.3s;
    }

    .feature-card:hover {
        transform: translateY(-5px);
        border-color: rgba(0, 217, 255, 0.45);
        box-shadow: 0 15px 40px rgba(0, 180, 255, 0.08);
    }

    .feature-card .icon {
        font-size: 28px;
        margin-bottom: 20px;
    }

    .feature-card h3 {
        font-size: 17px;
    }

    .feature-card p {
        margin-top: 10px;
        color: #7e91aa;
        font-size: 13px;
        line-height: 1.6;
    }

    .workflow-box {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 15px;
        padding: 35px;
        background: #0b1424;
        border: 1px solid #17283f;
        border-radius: 15px;
        overflow-x: auto;
    }

    .step {
        min-width: 100px;
        text-align: center;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }

    .step b {
        display: block;
        color: #00d9ff;
    }

    .arrow {
        color: #304963;
        font-size: 22px;
    }

    .status-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 18px;
    }

    .status-card {
        padding: 25px;
        background: #0b1424;
        border: 1px solid #17283f;
        border-radius: 13px;
    }

    .status-card span {
        color: #7589a2;
        font-size: 13px;
    }

    .status-card strong {
        display: block;
        margin-top: 10px;
        font-size: 32px;
        color: #00d9ff;
    }

    .status-card.green strong { color: #35e78b; }
    .status-card.orange strong { color: #ffad42; }
    .status-card.red strong { color: #ff4d5a; }

    footer {
        margin-top: 40px;
        padding: 24px 20px;
        text-align: center;
        background: #030710;
        border-top: 1px solid #15243a;
    }

    footer .logo {
        justify-content: center;
        margin-bottom: 10px;
    }

    footer p {
        margin: 10px 0;
        color: #657a94;
        font-size: 13px;
    }

    footer small {
        color: #40536c;
    }

    @media (max-width: 850px) {
        .hero {
            flex-direction: column;
            padding-top: 60px;
            text-align: center;
        }

        .hero-buttons {
            justify-content: center;
        }

        .security-card {
            width: 100%;
            max-width: 400px;
        }

        .features,
        .status-grid {
            grid-template-columns: 1fr 1fr;
        }
    }

    @media (max-width: 550px) {
        .navbar nav {
            display: none;
        }

        .hero h1 {
            font-size: 45px;
        }

        .hero-buttons {
            flex-direction: column;
        }

        .features,
        .status-grid {
            grid-template-columns: 1fr;
        }

        .workflow-box {
            justify-content: flex-start;
        }
    }
    </style>

    <div class="shadowtrust-shell">
        <div class="network-bg"></div>

        <header class="navbar">
            <div class="logo"><span>🛡️</span> ShadowTrust</div>

            <nav>
                <a href="#features">Features</a>
                <a href="#workflow">How It Works</a>
                <a href="#status">Status</a>
            </nav>

            <button class="login-btn">Login</button>
        </header>

        <section class="hero">
            <div class="hero-content">
                <div class="badge">● ADAPTIVE SECURITY SYSTEM</div>

                <h1>Trust Behavior.<br><span>Not Assumptions.</span></h1>

                <p>Adaptive behavioral security for <strong>Non-Human Identities.</strong></p>

                <div class="hero-buttons">
                    <button class="primary-btn">🚀 Start Monitoring</button>
                    <button class="secondary-btn">📊 View Dashboard</button>
                </div>

                <div class="system-status">
                    <span class="status-dot"></span>
                    System Protected
                </div>
            </div>

            <div class="security-card">
                <div class="card-header">
                    <span>SHADOWTRUST</span>
                    <span class="live">● LIVE</span>
                </div>

                <h3>Identity Security</h3>

                <div class="score">
                    <span>Trust Score</span>
                    <strong>92</strong>
                    <small>/100</small>
                </div>

                <div class="progress">
                    <div class="progress-bar"></div>
                </div>

                <div class="card-info">
                    <div>
                        <small>Current State</small>
                        <strong class="normal">NORMAL</strong>
                    </div>

                    <div>
                        <small>Baseline</small>
                        <strong>PROTECTED</strong>
                    </div>
                </div>
            </div>
        </section>

        <section id="features" class="section">
            <div class="section-title">
                <span>CORE CAPABILITIES</span>
                <h2>Intelligent Behavioral Protection</h2>
            </div>

            <div class="features">
                <div class="feature-card">
                    <div class="icon">🧠</div>
                    <h3>Behavioral Detection</h3>
                    <p>Detect unusual changes in identity behavior.</p>
                </div>

                <div class="feature-card">
                    <div class="icon">🕸️</div>
                    <h3>Relationship Graph</h3>
                    <p>Visualize connections between identities, resources and actions.</p>
                </div>

                <div class="feature-card">
                    <div class="icon">⭐</div>
                    <h3>Trust Credit Score</h3>
                    <p>Dynamically calculate the trust level of each identity.</p>
                </div>

                <div class="feature-card">
                    <div class="icon">🌑</div>
                    <h3>Shadow Profile</h3>
                    <p>Learn new behavior safely without changing the trusted baseline.</p>
                </div>

                <div class="feature-card">
                    <div class="icon">🚪</div>
                    <h3>Adaptation Gate</h3>
                    <p>Decide whether new behavior can influence the baseline.</p>
                </div>

                <div class="feature-card">
                    <div class="icon">📈</div>
                    <h3>Dual Timeline</h3>
                    <p>Compare recent activity with long-term trusted behavior.</p>
                </div>
            </div>
        </section>

        <section id="workflow" class="workflow section">
            <div class="section-title">
                <span>WORKFLOW</span>
                <h2>How ShadowTrust Works</h2>
            </div>

            <div class="workflow-box">
                <div class="step"><b>01</b><span>Activity</span></div>
                <div class="arrow">→</div>
                <div class="step"><b>02</b><span>Analyze</span></div>
                <div class="arrow">→</div>
                <div class="step"><b>03</b><span>Compare</span></div>
                <div class="arrow">→</div>
                <div class="step"><b>04</b><span>Score</span></div>
                <div class="arrow">→</div>
                <div class="step"><b>05</b><span>Gate</span></div>
                <div class="arrow">→</div>
                <div class="step"><b>06</b><span>Decide</span></div>
            </div>
        </section>

        <section id="status" class="section">
            <div class="section-title">
                <span>LIVE MONITORING</span>
                <h2>Identity Security Status</h2>
            </div>

            <div class="status-grid">
                <div class="status-card">
                    <span>Identities Monitored</span>
                    <strong>128</strong>
                </div>

                <div class="status-card green">
                    <span>Normal</span>
                    <strong>94</strong>
                </div>

                <div class="status-card orange">
                    <span>Drifting</span>
                    <strong>21</strong>
                </div>

                <div class="status-card red">
                    <span>Suspicious</span>
                    <strong>9</strong>
                </div>
            </div>
        </section>

        <footer>
            <div class="logo">🛡️ ShadowTrust</div>
            <p>Adaptive Behavioral Trust for Non-Human Identities</p>
            <small>© 2026 ShadowTrust. Hackathon Prototype.</small>
        </footer>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SESSION STATE
# ============================================================

if "engine" not in st.session_state:
    st.session_state.engine = ShadowTrustEngine()
    st.session_state.running = False
    st.session_state.baseline_loaded = False

engine = st.session_state.engine


def initialize_baseline_if_needed():
    if st.session_state.baseline_loaded:
        return

    baseline_df = generate_synthetic_data(
        num_identities=6,
        events_per_identity=40
    )

    engine.initialize_baseline(
        baseline_df.to_dict("records")
    )

    for event in baseline_df.to_dict("records"):
        engine.process_event(event)

    st.session_state.baseline_loaded = True


if st.session_state.pop("load_demo_from_landing", False):
    initialize_baseline_if_needed()
    st.toast("Demo baseline loaded. Live trust dashboard is ready.", icon=":material/verified_user:")


# ============================================================
# SIDEBAR CONTROLS
# ============================================================

with st.sidebar:
    st.markdown('<div class="sidebar-brand">SHADOWTRUST</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-kicker">BEHAVIORAL SECURITY</div>', unsafe_allow_html=True)
    st.space("small")
    st.badge("System protected", icon=":material/verified_user:", color="green")
    st.markdown("#### Navigation")
    st.markdown(
        """
        <div class="nav-tree">
            <div class="nav-item"><span class="nav-arrow">&gt;&gt;&gt;</span> Core capabilities</div>
            <div class="nav-item"><span class="nav-arrow">&gt;&gt;&gt;</span> Features</div>
            <div class="nav-item"><span class="nav-arrow">&gt;&gt;&gt;</span> How it works</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.space("small")
    sidebar_start = st.button(
        "Start monitoring",
        icon=":material/play_arrow:",
        type="primary",
        width="stretch",
        key="sidebar_start_monitoring",
    )
    sidebar_dashboard = st.button(
        "View dashboard",
        icon=":material/dashboard:",
        width="stretch",
        key="sidebar_view_dashboard",
    )
    sidebar_login = st.button(
        "Login",
        icon=":material/login:",
        width="stretch",
        key="sidebar_login",
    )
    st.markdown(
        """
        <div class="notification-card">
            <div class="notification-title">SYSTEM STATUS</div>
            <div class="notification-row"><span>Identities monitored</span><strong>128</strong></div>
            <div class="notification-row"><span>Normal</span><strong style="color:#35e78b">94</strong></div>
            <div class="notification-row"><span>Drifting</span><strong style="color:#ffad42">21</strong></div>
            <div class="notification-row"><span>Suspicious</span><strong style="color:#ff704d">9</strong></div>
            <div class="notification-row"><span>High-risk</span><strong style="color:#ff4d5a">4</strong></div>
            <div class="notification-row"><span>Baseline updates</span><strong class="protected-text">PROTECTED</strong></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

if sidebar_start or sidebar_dashboard:
    initialize_baseline_if_needed()
    st.toast("Demo baseline loaded. Live trust dashboard is ready.", icon=":material/verified_user:")
if sidebar_login:
    st.toast("Login will be available when identity authentication is connected.", icon=":material/login:")

with st.sidebar.expander("⋮  Controls", expanded=False):
    with st.form("activity_form"):
        identity = st.text_input("Identity", value="svc-01")
        resource = st.text_input("Resource", value="database")
        action = st.selectbox("Action", ["READ", "WRITE", "UPDATE", "DELETE", "LIST"])
        timestamp_input = st.text_input("Timestamp (optional)", value="")
        submitted = st.form_submit_button("▶️ Process event")

if submitted:
    initialize_baseline_if_needed()

    parsed_timestamp = (
        pd.Timestamp(timestamp_input)
        if timestamp_input.strip()
        else datetime.now()
    )

    event = {
        "timestamp": parsed_timestamp,
        "identity": identity.strip() or "svc-01",
        "resource": resource.strip() or "database",
        "action": action
    }

    result = engine.process_event(event)
    backend_result = process_event_through_backend(event)
    if backend_result:
        st.session_state.last_backend_decision = backend_result

    st.sidebar.success(
        f"Event processed for {event['identity']}"
    )

with st.sidebar.expander("⋮  Demo tools", expanded=False):
    load_demo = st.button("🧪 Load demo baseline")
    simulate_attack = st.button("🚨 Simulate Attack")

if load_demo:
    initialize_baseline_if_needed()
    st.sidebar.success("Baseline loaded.")

if simulate_attack:
    initialize_baseline_if_needed()

    attack_df = inject_attack(
        pd.DataFrame(
            columns=[
                "timestamp",
                "identity",
                "resource",
                "action"
            ]
        ),
        identity="svc-01"
    )

    for event in attack_df.to_dict("records"):
        result = engine.process_event(event)
        backend_result = process_event_through_backend(event)
        if backend_result:
            st.session_state.last_backend_decision = backend_result

    st.sidebar.success(
        "Attack simulation completed."
    )


if not st.session_state.baseline_loaded:
    st.info("Provide the identity and activity details in the sidebar, then click Process event to start the model.")
    st.stop()


# ============================================================
# METRICS
# ============================================================

st.markdown("## 📊 Live Trust Dashboard")
st.caption("The live model results below are based on the activity submitted in the sidebar.")
st.markdown("### SHADOWTRUST - BASELINE POISONING RESISTANCE")

summary = engine.get_identity_summary()
events_df = engine.get_events_df()

normal_count = 0
drifting_count = 0
suspicious_count = 0
high_risk_count = 0

if not events_df.empty:

    normal_count = len(
        events_df[
            events_df["state"] == "NORMAL"
        ]
    )

    drifting_count = len(
        events_df[
            events_df["state"] == "DRIFTING"
        ]
    )

    suspicious_count = len(
        events_df[
            events_df["state"] == "SUSPICIOUS"
        ]
    )

    high_risk_count = len(
        events_df[
            events_df["state"] == "HIGH-RISK"
        ]
    )


col1, col2, col3, col4, col5 = st.columns(5)

col1.metric(
    "Identities",
    len(engine.profiles)
)

col2.metric(
    "🟢 Normal",
    normal_count
)

col3.metric(
    "🟡 Drifting",
    drifting_count
)

col4.metric(
    "🟠 Suspicious",
    suspicious_count
)

col5.metric(
    "🔴 High Risk",
    high_risk_count
)

st.header("Security operations overview")
st.caption("Coverage map for the ShadowTrust behavioral-security console.")
st.markdown(
    """
    <div class="ops-grid">
        <div class="ops-card"><span>TRUST</span>Trust score</div>
        <div class="ops-card"><span>MONITOR</span>NHI monitoring</div>
        <div class="ops-card"><span>TIMELINE</span>Stable timeline</div>
        <div class="ops-card"><span>TIMELINE</span>Active timeline</div>
        <div class="ops-card"><span>COMPARE</span>Behavioral comparison</div>
        <div class="ops-card"><span>GRAPH</span>Behavioral relationship graph</div>
        <div class="ops-card"><span>ISOLATE</span>Shadow profile</div>
        <div class="ops-card"><span>VERIFY</span>Adaptation gate</div>
        <div class="ops-card"><span>DETECT</span>Risk detection</div>
        <div class="ops-card"><span>ALERT</span>Alert center</div>
        <div class="ops-card"><span>PROTECT</span>Baseline protection</div>
        <div class="ops-card"><span>DETECT</span>Anomaly detection</div>
        <div class="ops-card"><span>HISTORY</span>Trust score history</div>
        <div class="ops-card"><span>LOGS</span>NHI activity logs</div>
        <div class="ops-card"><span>ANALYZE</span>Risk analytics</div>
        <div class="ops-card"><span>EXPLAIN</span>Human-readable explanation</div>
        <div class="ops-card"><span>THREATS</span>Attack / threat timeline</div>
        <div class="ops-card"><span>ACCESS</span>Resource access monitoring</div>
        <div class="ops-card"><span>RELATIONSHIPS</span>New relationship detection</div>
        <div class="ops-card"><span>STATUS</span>Security status overview</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# IDENTITY TRUST TABLE
# ============================================================

st.header("Identity Trust Overview")

if not summary.empty:

    def color_state(value):

        colors = {
            "NORMAL": "background-color: #14532d; color: white",
            "DRIFTING": "background-color: #a16207; color: white",
            "SUSPICIOUS": "background-color: #c2410c; color: white",
            "HIGH-RISK": "background-color: #991b1b; color: white"
        }

        return colors.get(value, "")

    st.dataframe(
        summary.style.map(
            color_state,
            subset=["State"]
        ),
        width="stretch"
    )


# ============================================================
# BEHAVIORAL GRAPH
# ============================================================

st.header("🕸️ Behavioral Relationship Graph")

G = engine.graph

if len(G.nodes) > 0:

    positions = nx.spring_layout(
        G,
        seed=42,
        k=1.5
    )

    edge_x = []
    edge_y = []

    for source, target in G.edges():

        x0, y0 = positions[source]
        x1, y1 = positions[target]

        edge_x += [
            x0,
            x1,
            None
        ]

        edge_y += [
            y0,
            y1,
            None
        ]

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(
            width=1,
            color="#64748b"
        ),
        hoverinfo="none",
        mode="lines"
    )

    node_x = []
    node_y = []
    node_color = []
    node_text = []

    for node in G.nodes():

        x, y = positions[node]

        node_x.append(x)
        node_y.append(y)

        node_type = G.nodes[node].get(
            "node_type",
            "resource"
        )

        if node_type == "identity":

            node_color.append("#22c55e")

            profile = engine.profiles.get(
                node
            )

            state = (
                profile.state
                if profile
                else "UNKNOWN"
            )

            node_text.append(
                f"Identity: {node}<br>"
                f"State: {state}"
            )

        else:

            node_color.append("#38bdf8")

            node_text.append(
                f"Resource: {node}"
            )

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=list(G.nodes()),
        textposition="top center",
        hovertext=node_text,
        hoverinfo="text",
        marker=dict(
            size=25,
            color=node_color,
            line=dict(
                width=2,
                color="white"
            )
        )
    )

    fig = go.Figure(
        data=[
            edge_trace,
            node_trace
        ]
    )

    fig.update_layout(
        height=600,
        template="plotly_dark",
        showlegend=False,
        xaxis=dict(
            showgrid=False,
            zeroline=False,
            visible=False
        ),
        yaxis=dict(
            showgrid=False,
            zeroline=False,
            visible=False
        )
    )

    st.plotly_chart(
        fig,
        width="stretch"
    )


# ============================================================
# SELECT IDENTITY
# ============================================================

st.header("🔎 Identity Investigation")

selected_identity = st.selectbox(
    "Select Non-Human Identity",
    list(engine.profiles.keys())
)

profile = engine.profiles[
    selected_identity
]


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Trust Credit",
    f"{profile.trust_credit:.1f}"
)

col2.metric(
    "Stable Resources",
    len(profile.stable_resources)
)

col3.metric(
    "Shadow Resources",
    len(profile.shadow_resources)
)

col4.metric(
    "Blocked Updates",
    profile.blocked_updates
)


# ============================================================
# TIMELINES
# ============================================================

timeline_col1, timeline_col2 = st.columns(2)

with timeline_col1:

    st.subheader("🟢 Stable Timeline")

    for resource in sorted(
        profile.stable_resources
    ):

        st.write(
            f"✓ {resource}"
        )

with timeline_col2:

    st.subheader("👤 Shadow Profile")

    if profile.shadow_resources:

        for resource in sorted(
            profile.shadow_resources
        ):

            st.write(
                f"⚠ {resource}"
            )

    else:

        st.info(
            "No untrusted behavior currently "
            "waiting for adaptation."
        )


# ============================================================
# RECENT EVENTS
# ============================================================

st.header("📡 Recent Activity")

if not events_df.empty:

    identity_events = events_df[
        events_df["identity"]
        == selected_identity
    ].tail(20)

    display_columns = [
        "timestamp",
        "resource",
        "action",
        "state",
        "novelty_score",
        "graph_risk",
        "trust_credit",
        "baseline_update"
    ]

    st.dataframe(
        identity_events[
            display_columns
        ],
        width="stretch"
    )


# ============================================================
# USER-FACING EXPLANATION
# ============================================================

st.header("🧠 Why This Decision?")

if not events_df.empty:

    latest = events_df[
        events_df["identity"]
        == selected_identity
    ].tail(1)

    if not latest.empty:

        latest_event = latest.iloc[0]
        explanation = latest_event["explanation"]
        state = latest_event["state"]

        if state == "NORMAL":
            st.success(explanation)
        elif state == "DRIFTING":
            st.warning(explanation)
        elif state == "SUSPICIOUS":
            st.error(explanation)
        else:
            st.error("🚨 HIGH-RISK: " + explanation)

# ============================================================
# ADAPTATION GATE
# ============================================================

st.header("🚪 Adaptation Gate")

if profile.state == "NORMAL":

    st.success(
        "ALLOW — behavior matches trusted baseline."
    )

elif profile.state == "DRIFTING":

    if profile.trust_credit >= 70:

        st.warning(
            "CONDITIONAL — legitimate drift may "
            "be incorporated if trust remains high."
        )

else:

    st.error(
        "BLOCK — HIGH-RISK behavior detected. "
        "Baseline is protected."
    )


