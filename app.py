import time
from datetime import datetime

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
    page_icon="🛡️",
    layout="wide"
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
        min-height: 650px;
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
        margin: 100px auto 0;
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
        margin-top: 100px;
        padding: 45px 20px;
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


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.header("⚙️ Controls")

with st.sidebar.form("activity_form"):
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

if st.sidebar.button("🧪 Load demo baseline"):
    initialize_baseline_if_needed()
    st.sidebar.success("Baseline loaded.")

if st.sidebar.button("🚨 Simulate Attack"):
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
        use_container_width=True
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
        use_container_width=True
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
        use_container_width=True
    )


# ============================================================
# EXPLANATION
# ============================================================

st.header("🧠 Model Decision Trace")

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
            "BLOCK — trust credit is too low."
        )

elif profile.state == "SUSPICIOUS":

    st.error(
        "BLOCK — suspicious behavior cannot "
        "modify the trusted baseline."
    )

else:

    st.error(
        "BLOCK — HIGH-RISK behavior detected. "
        "Baseline is protected."
    )


