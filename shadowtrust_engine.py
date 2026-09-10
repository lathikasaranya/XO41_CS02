import random
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import networkx as nx
import numpy as np
import pandas as pd


# ============================================================
# DATA MODEL
# ============================================================

@dataclass
class NHIProfile:
    identity: str

    # Long-term trusted behavior
    stable_resources: set = field(default_factory=set)
    stable_actions: set = field(default_factory=set)
    stable_hours: list = field(default_factory=list)
    stable_frequency: float = 0.0

    # Recent behavior
    active_events: deque = field(default_factory=lambda: deque(maxlen=50))

    # Shadow learning area
    shadow_resources: set = field(default_factory=set)
    shadow_actions: set = field(default_factory=set)

    # Reputation
    trust_credit: float = 80.0

    # Current state
    state: str = "NORMAL"

    # Statistics
    total_events: int = 0
    suspicious_events: int = 0
    blocked_updates: int = 0
    accepted_updates: int = 0


# ============================================================
# SHADOWTRUST ENGINE
# ============================================================

class ShadowTrustEngine:

    def __init__(self):
        self.profiles = {}
        self.graph = nx.DiGraph()
        self.events = []

        self.states = [
            "NORMAL",
            "DRIFTING",
            "SUSPICIOUS",
            "HIGH-RISK"
        ]

    # --------------------------------------------------------
    # REGISTER NHI
    # --------------------------------------------------------

    def register_identity(self, identity):

        if identity not in self.profiles:
            self.profiles[identity] = NHIProfile(identity=identity)

    # --------------------------------------------------------
    # FEATURE EXTRACTION
    # --------------------------------------------------------

    def extract_features(self, event):

        timestamp = pd.to_datetime(event["timestamp"])

        return {
            "identity": event["identity"],
            "resource": event["resource"],
            "action": event["action"],
            "hour": timestamp.hour,
            "day": timestamp.dayofweek,
            "timestamp": timestamp,
        }

    # --------------------------------------------------------
    # BEHAVIORAL RELATIONSHIP GRAPH
    # --------------------------------------------------------

    def update_graph(self, features):

        identity = features["identity"]
        resource = features["resource"]
        action = features["action"]

        self.graph.add_node(
            identity,
            node_type="identity"
        )

        self.graph.add_node(
            resource,
            node_type="resource"
        )

        # Identity -> Resource
        if self.graph.has_edge(identity, resource):

            self.graph[identity][resource]["weight"] += 1

            actions = self.graph[identity][resource].get(
                "actions",
                []
            )

            actions.append(action)

            self.graph[identity][resource]["actions"] = actions

        else:

            self.graph.add_edge(
                identity,
                resource,
                weight=1,
                actions=[action]
            )

    # --------------------------------------------------------
    # BASELINE INITIALIZATION
    # --------------------------------------------------------

    def initialize_baseline(self, events):

        df = pd.DataFrame(events)

        if df.empty:
            return

        for identity, group in df.groupby("identity"):

            self.register_identity(identity)

            profile = self.profiles[identity]

            profile.stable_resources = set(
                group["resource"].unique()
            )

            profile.stable_actions = set(
                group["action"].unique()
            )

            timestamps = pd.to_datetime(group["timestamp"])

            profile.stable_hours = list(
                timestamps.dt.hour.unique()
            )

            profile.stable_frequency = len(group) / max(
                (timestamps.max() - timestamps.min()).total_seconds() / 3600,
                1
            )

    # --------------------------------------------------------
    # TIMELINE COMPARISON
    # --------------------------------------------------------

    def compare_timelines(self, profile, features):

        resource = features["resource"]
        action = features["action"]
        hour = features["hour"]

        resource_known = resource in profile.stable_resources
        action_known = action in profile.stable_actions
        hour_known = hour in profile.stable_hours

        novelty = 0

        if not resource_known:
            novelty += 40

        if not action_known:
            novelty += 25

        if not hour_known:
            novelty += 15

        # Completely new behavior
        if novelty >= 65:
            state = "SUSPICIOUS"

        elif novelty >= 30:
            state = "DRIFTING"

        else:
            state = "NORMAL"

        return state, novelty

    # --------------------------------------------------------
    # SHADOW PROFILE
    # --------------------------------------------------------

    def update_shadow_profile(self, profile, features):

        profile.shadow_resources.add(
            features["resource"]
        )

        profile.shadow_actions.add(
            features["action"]
        )

    # --------------------------------------------------------
    # GRAPH RISK
    # --------------------------------------------------------

    def graph_risk(self, features):

        identity = features["identity"]
        resource = features["resource"]

        if self.graph.has_edge(identity, resource):

            weight = self.graph[identity][resource]["weight"]

            # Frequently used relationship
            if weight >= 5:
                return 0

            return 10

        # Completely new relationship
        return 30

    # --------------------------------------------------------
    # TRUST CREDIT SCORE
    # --------------------------------------------------------

    def update_trust_credit(
        self,
        profile,
        state,
        novelty,
        graph_risk
    ):

        penalty = novelty * 0.25 + graph_risk * 0.35

        if state == "NORMAL":

            profile.trust_credit += 2

        elif state == "DRIFTING":

            profile.trust_credit -= penalty * 0.5

        elif state == "SUSPICIOUS":

            profile.trust_credit -= penalty

        elif state == "HIGH-RISK":

            profile.trust_credit -= penalty * 1.5

        profile.trust_credit = max(
            0,
            min(100, profile.trust_credit)
        )

    # --------------------------------------------------------
    # HIGH-RISK ESCALATION
    # --------------------------------------------------------

    def calculate_final_state(
        self,
        state,
        profile,
        novelty,
        graph_risk
    ):

        risk_score = (
            novelty * 0.5
            + graph_risk * 0.5
        )

        if profile.trust_credit < 30:
            risk_score += 25

        if risk_score >= 75:
            return "HIGH-RISK"

        if risk_score >= 45:
            return "SUSPICIOUS"

        if risk_score >= 20:
            return "DRIFTING"

        return "NORMAL"

    # --------------------------------------------------------
    # ADAPTATION GATE
    # --------------------------------------------------------

    def adaptation_gate(
        self,
        profile,
        state,
        novelty
    ):

        # NORMAL behavior is safe
        if state == "NORMAL":
            return True, "Behavior matches trusted baseline."

        # Suspicious and high-risk never update baseline
        if state in ["SUSPICIOUS", "HIGH-RISK"]:
            return False, "Unsafe behavior rejected by adaptation gate."

        # DRIFTING requires sufficient trust
        if state == "DRIFTING":

            if profile.trust_credit >= 70 and novelty < 40:
                return True, (
                    "Legitimate behavioral drift accepted "
                    "because trust remains high."
                )

            return False, (
                "Behavior is drifting but trust is insufficient "
                "for automatic baseline adaptation."
            )

        return False, "Unknown state."

    # --------------------------------------------------------
    # BASELINE UPDATE
    # --------------------------------------------------------

    def update_baseline(
        self,
        profile,
        features
    ):

        profile.stable_resources.add(
            features["resource"]
        )

        profile.stable_actions.add(
            features["action"]
        )

        if features["hour"] not in profile.stable_hours:

            profile.stable_hours.append(
                features["hour"]
            )

        profile.accepted_updates += 1

        # Once accepted, shadow behavior becomes trusted
        profile.shadow_resources.discard(
            features["resource"]
        )

        profile.shadow_actions.discard(
            features["action"]
        )

    # --------------------------------------------------------
    # EXPLANATION
    # --------------------------------------------------------

    def generate_explanation(
        self,
        features,
        state,
        novelty,
        graph_risk,
        gate_allowed,
        gate_reason,
        profile
    ):

        reasons = []

        if features["resource"] not in profile.stable_resources:
            reasons.append(
                f"new resource '{features['resource']}'"
            )

        if features["action"] not in profile.stable_actions:
            reasons.append(
                f"new action '{features['action']}'"
            )

        if features["hour"] not in profile.stable_hours:
            reasons.append(
                "unusual access time"
            )

        if graph_risk >= 30:
            reasons.append(
                "new identity-resource relationship"
            )

        if not reasons:
            reasons.append(
                "behavior closely matches the trusted baseline"
            )

        decision = (
            "BASELINE UPDATE ALLOWED"
            if gate_allowed
            else "BASELINE UPDATE BLOCKED"
        )

        return (
            f"State: {state}. "
            f"Reason: {', '.join(reasons)}. "
            f"Novelty score: {novelty}. "
            f"Graph risk: {graph_risk}. "
            f"Trust credit: {profile.trust_credit:.1f}. "
            f"{decision}. {gate_reason}"
        )

    # --------------------------------------------------------
    # PROCESS EVENT
    # --------------------------------------------------------

    def process_event(self, event):

        features = self.extract_features(event)

        identity = features["identity"]

        self.register_identity(identity)

        profile = self.profiles[identity]

        profile.total_events += 1

        # Compare stable vs active
        initial_state, novelty = self.compare_timelines(
            profile,
            features
        )

        # Score relationship novelty before the observation is added to
        # the graph; otherwise every relationship appears already known.
        graph_risk = self.graph_risk(features)

        # Record the observed identity-resource relationship after scoring.
        self.update_graph(features)

        # Learn safely inside shadow profile
        self.update_shadow_profile(
            profile,
            features
        )

        # Update reputation
        self.update_trust_credit(
            profile,
            initial_state,
            novelty,
            graph_risk
        )

        # Final state
        final_state = self.calculate_final_state(
            initial_state,
            profile,
            novelty,
            graph_risk
        )

        profile.state = final_state

        if final_state in ["SUSPICIOUS", "HIGH-RISK"]:
            profile.suspicious_events += 1

        # Adaptation Gate
        allowed, gate_reason = self.adaptation_gate(
            profile,
            final_state,
            novelty
        )

        if allowed:

            self.update_baseline(
                profile,
                features
            )

        else:

            profile.blocked_updates += 1

        # Explanation
        explanation = self.generate_explanation(
            features,
            final_state,
            novelty,
            graph_risk,
            allowed,
            gate_reason,
            profile
        )

        # Active timeline
        profile.active_events.append({
            **features,
            "state": final_state,
            "novelty": novelty,
            "graph_risk": graph_risk,
            "trust_credit": profile.trust_credit,
            "baseline_update": allowed
        })

        result = {
            **event,
            "state": final_state,
            "novelty_score": novelty,
            "graph_risk": graph_risk,
            "trust_credit": round(
                profile.trust_credit,
                2
            ),
            "baseline_update": allowed,
            "explanation": explanation
        }

        self.events.append(result)

        return result

    # --------------------------------------------------------
    # GET DASHBOARD DATA
    # --------------------------------------------------------

    def get_events_df(self):

        if not self.events:
            return pd.DataFrame()

        return pd.DataFrame(self.events)

    def get_identity_summary(self):

        rows = []

        for identity, profile in self.profiles.items():

            rows.append({
                "Identity": identity,
                "State": profile.state,
                "Trust Credit": round(
                    profile.trust_credit,
                    2
                ),
                "Stable Resources": len(
                    profile.stable_resources
                ),
                "Shadow Resources": len(
                    profile.shadow_resources
                ),
                "Events": profile.total_events,
                "Suspicious": profile.suspicious_events,
                "Blocked Updates": profile.blocked_updates,
                "Accepted Updates": profile.accepted_updates
            })

        return pd.DataFrame(rows)


# ============================================================
# SYNTHETIC DATA GENERATOR
# ============================================================

def generate_synthetic_data(
    num_identities=6,
    events_per_identity=40
):

    identities = [
        f"svc-{i:02d}"
        for i in range(1, num_identities + 1)
    ]

    resources = [
        "database",
        "payment-api",
        "user-api",
        "storage",
        "logging",
        "analytics"
    ]

    actions = [
        "READ",
        "WRITE",
        "UPDATE",
        "LIST"
    ]

    rows = []

    base_time = datetime.now() - timedelta(days=7)

    for identity in identities:

        normal_resources = random.sample(
            resources,
            k=2
        )

        normal_actions = random.sample(
            actions,
            k=2
        )

        for i in range(events_per_identity):

            timestamp = base_time + timedelta(
                hours=random.randint(
                    0,
                    24 * 7
                ),
                minutes=random.randint(
                    0,
                    59
                )
            )

            resource = random.choice(
                normal_resources
            )

            action = random.choice(
                normal_actions
            )

            rows.append({
                "timestamp": timestamp,
                "identity": identity,
                "resource": resource,
                "action": action
            })

    return pd.DataFrame(rows)


# ============================================================
# ATTACK / DRIFT SIMULATOR
# ============================================================

def inject_attack(
    df,
    identity="svc-01"
):

    attack_events = []

    now = datetime.now()

    # Gradual baseline poisoning
    for i in range(8):

        attack_events.append({
            "timestamp": now + timedelta(
                minutes=i * 10
            ),
            "identity": identity,
            "resource": "secrets-vault",
            "action": "READ"
        })

    # Sudden suspicious activity
    attack_events.append({
        "timestamp": now + timedelta(
            minutes=100
        ),
        "identity": identity,
        "resource": "admin-database",
        "action": "DELETE"
    })

    attack_events.append({
        "timestamp": now + timedelta(
            minutes=110
        ),
        "identity": identity,
        "resource": "production-cluster",
        "action": "WRITE"
    })

    return pd.concat(
        [
            df,
            pd.DataFrame(attack_events)
        ],
        ignore_index=True
    )
