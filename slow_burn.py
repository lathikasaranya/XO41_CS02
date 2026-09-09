"""
============================================================
SHADOWTRUST
BASELINE POISONING RESISTANCE
============================================================

Goal:
    Prevent compromised NHI behavior from becoming part
    of the trusted behavioral baseline.

Attack:
    An attacker gradually performs malicious actions and
    tries to make those actions look normal.

Defense:
    1. New behavior goes into Shadow Profile first.
    2. Stable baseline is NOT updated immediately.
    3. Behavioral evidence accumulates.
    4. Trust score is evaluated.
    5. Adaptation Gate makes the final decision.
    6. Suspicious / HIGH-RISK behavior is rejected.
    7. Only sufficiently trusted behavior can enter
       the Stable Timeline.

============================================================
"""

from dataclasses import dataclass, field
from collections import Counter, deque
from datetime import datetime
from typing import List


# ============================================================
# CONFIGURATION
# ============================================================

INITIAL_TRUST = 100.0

MIN_TRUST_FOR_ADAPTATION = 70.0

MIN_REPETITIONS_FOR_ADAPTATION = 4

MAX_SHADOW_RISK = 0.30

SUSPICIOUS_THRESHOLD = 0.50

HIGH_RISK_THRESHOLD = 0.75

EVIDENCE_DECAY = 0.90


# ============================================================
# ACTIVITY
# ============================================================

@dataclass
class Activity:

    identity: str
    resource: str
    action: str
    hour: int

    timestamp: str = field(
        default_factory=lambda:
        datetime.now().isoformat()
    )


# ============================================================
# BASELINE PROFILE
# ============================================================

class BaselineProfile:

    def __init__(self, identity):

        self.identity = identity

        # ----------------------------------------------------
        # TRUSTED / STABLE BASELINE
        # ----------------------------------------------------

        self.stable_resources = Counter()
        self.stable_actions = Counter()
        self.stable_hours = Counter()

        self.stable_timeline = []

        # ----------------------------------------------------
        # SHADOW PROFILE
        #
        # New behavior is isolated here.
        # ----------------------------------------------------

        self.shadow_resources = Counter()
        self.shadow_actions = Counter()
        self.shadow_hours = Counter()

        self.shadow_timeline = []

        # ----------------------------------------------------
        # SECURITY STATE
        # ----------------------------------------------------

        self.trust_score = INITIAL_TRUST

        self.risk_score = 0.0

        self.state = "NORMAL"

        # ----------------------------------------------------
        # POISONING PROTECTION
        # ----------------------------------------------------

        self.blocked_baseline_updates = 0

        self.approved_baseline_updates = 0

        self.poisoning_attempts = 0

        # ----------------------------------------------------
        # HISTORY
        # ----------------------------------------------------

        self.decision_history = []


# ============================================================
# SHADOWTRUST BASELINE PROTECTION ENGINE
# ============================================================

class BaselineProtection:

    def __init__(self):

        self.profiles = {}

    # ========================================================
    # PROFILE
    # ========================================================

    def get_profile(self, identity):

        if identity not in self.profiles:

            self.profiles[identity] = (
                BaselineProfile(identity)
            )

        return self.profiles[identity]

    # ========================================================
    # ESTABLISH TRUSTED BASELINE
    # ========================================================

    def establish_baseline(
        self,
        identity,
        activities: List[Activity]
    ):

        profile = self.get_profile(identity)

        for activity in activities:

            profile.stable_timeline.append(
                activity
            )

            profile.stable_resources[
                activity.resource
            ] += 1

            profile.stable_actions[
                activity.action
            ] += 1

            profile.stable_hours[
                activity.hour
            ] += 1

    # ========================================================
    # CHECK WHETHER RESOURCE IS NEW
    # ========================================================

    def is_new_resource(
        self,
        profile,
        activity
    ):

        return (
            activity.resource
            not in
            profile.stable_resources
        )

    # ========================================================
    # CHECK WHETHER ACTION IS NEW
    # ========================================================

    def is_new_action(
        self,
        profile,
        activity
    ):

        return (
            activity.action
            not in
            profile.stable_actions
        )

    # ========================================================
    # CHECK WHETHER TIME IS NEW
    # ========================================================

    def is_new_time(
        self,
        profile,
        activity
    ):

        if not profile.stable_hours:

            return False

        return (
            activity.hour
            not in
            profile.stable_hours
        )

    # ========================================================
    # CALCULATE BEHAVIORAL RISK
    # ========================================================

    def calculate_risk(
        self,
        profile,
        activity
    ):

        risk = 0.0

        reasons = []

        # ----------------------------------------------------
        # New resource
        # ----------------------------------------------------

        if self.is_new_resource(
            profile,
            activity
        ):

            risk += 0.25

            reasons.append(
                "resource is not present "
                "in trusted baseline"
            )

        # ----------------------------------------------------
        # New action
        # ----------------------------------------------------

        if self.is_new_action(
            profile,
            activity
        ):

            risk += 0.20

            reasons.append(
                "action is not present "
                "in trusted baseline"
            )

        # ----------------------------------------------------
        # New access time
        # ----------------------------------------------------

        if self.is_new_time(
            profile,
            activity
        ):

            risk += 0.10

            reasons.append(
                "access time differs "
                "from trusted behavior"
            )

        # ----------------------------------------------------
        # Dangerous resources
        # ----------------------------------------------------

        dangerous_resources = {
            "credential-store",
            "secret-vault",
            "admin-database",
            "production-cluster"
        }

        if activity.resource in dangerous_resources:

            risk += 0.30

            reasons.append(
                "sensitive resource accessed"
            )

        # ----------------------------------------------------
        # Dangerous actions
        # ----------------------------------------------------

        dangerous_actions = {
            "EXPORT",
            "DELETE",
            "PRIVILEGED_READ",
            "CREDENTIAL_DUMP"
        }

        if activity.action in dangerous_actions:

            risk += 0.30

            reasons.append(
                "high-impact action detected"
            )

        return min(
            1.0,
            risk
        ), reasons

    # ========================================================
    # SHADOW PROFILE
    # ========================================================

    def update_shadow_profile(
        self,
        profile,
        activity
    ):

        profile.shadow_timeline.append(
            activity
        )

        profile.shadow_resources[
            activity.resource
        ] += 1

        profile.shadow_actions[
            activity.action
        ] += 1

        profile.shadow_hours[
            activity.hour
        ] += 1

    # ========================================================
    # COUNT REPEATED BEHAVIOR
    # ========================================================

    def behavior_repetitions(
        self,
        profile,
        activity
    ):

        return profile.shadow_resources[
            activity.resource
        ]

    # ========================================================
    # ADAPTATION GATE
    # ========================================================

    def adaptation_gate(
        self,
        profile,
        activity,
        risk
    ):

        # ----------------------------------------------------
        # RULE 1:
        # High-risk behavior can NEVER modify baseline.
        # ----------------------------------------------------

        if risk >= HIGH_RISK_THRESHOLD:

            return False, (
                "BLOCKED: high-risk behavior "
                "cannot modify trusted baseline"
            )

        # ----------------------------------------------------
        # RULE 2:
        # Suspicious behavior cannot modify baseline.
        # ----------------------------------------------------

        if risk >= SUSPICIOUS_THRESHOLD:

            return False, (
                "BLOCKED: suspicious behavior "
                "cannot modify trusted baseline"
            )

        # ----------------------------------------------------
        # RULE 3:
        # Trust must remain high.
        # ----------------------------------------------------

        if (
            profile.trust_score
            < MIN_TRUST_FOR_ADAPTATION
        ):

            return False, (
                "BLOCKED: trust score is below "
                "adaptation threshold"
            )

        # ----------------------------------------------------
        # RULE 4:
        # New behavior must be observed repeatedly.
        # ----------------------------------------------------

        repetitions = (
            self.behavior_repetitions(
                profile,
                activity
            )
        )

        if repetitions < MIN_REPETITIONS_FOR_ADAPTATION:

            return False, (
                "BLOCKED: insufficient repeated "
                "evidence for baseline adaptation"
            )

        # ----------------------------------------------------
        # RULE 5:
        # Shadow behavior must remain low risk.
        # ----------------------------------------------------

        if risk > MAX_SHADOW_RISK:

            return False, (
                "BLOCKED: shadow behavior "
                "exceeds safe risk threshold"
            )

        return True, (
            "ALLOWED: behavior has sufficient "
            "trusted evidence"
        )

    # ========================================================
    # UPDATE TRUST SCORE
    # ========================================================

    def update_trust(
        self,
        profile,
        risk
    ):

        if risk == 0:

            profile.trust_score += 1

        elif risk < 0.30:

            profile.trust_score -= 1

        elif risk < 0.50:

            profile.trust_score -= 4

        else:

            profile.trust_score -= 10

        profile.trust_score = max(
            0,
            min(
                100,
                profile.trust_score
            )
        )

    # ========================================================
    # COMMIT TO STABLE BASELINE
    # ========================================================

    def commit_to_baseline(
        self,
        profile,
        activity
    ):

        profile.stable_timeline.append(
            activity
        )

        profile.stable_resources[
            activity.resource
        ] += 1

        profile.stable_actions[
            activity.action
        ] += 1

        profile.stable_hours[
            activity.hour
        ] += 1

        profile.approved_baseline_updates += 1

    # ========================================================
    # PROCESS ACTIVITY
    # ========================================================

    def process(
        self,
        activity
    ):

        profile = self.get_profile(
            activity.identity
        )

        # ----------------------------------------------------
        # STEP 1
        # Calculate risk BEFORE changing baseline
        # ----------------------------------------------------

        risk, reasons = (
            self.calculate_risk(
                profile,
                activity
            )
        )

        # ----------------------------------------------------
        # STEP 2
        # Put behavior into shadow profile
        # ----------------------------------------------------

        self.update_shadow_profile(
            profile,
            activity
        )

        # ----------------------------------------------------
        # STEP 3
        # Update cumulative risk
        #
        # Old evidence slowly decays.
        # ----------------------------------------------------

        profile.risk_score *= (
            EVIDENCE_DECAY
        )

        profile.risk_score += (
            risk * 0.25
        )

        profile.risk_score = min(
            1.0,
            profile.risk_score
        )

        # ----------------------------------------------------
        # STEP 4
        # Determine state
        # ----------------------------------------------------

        if (
            profile.risk_score
            >= HIGH_RISK_THRESHOLD
        ):

            profile.state = "HIGH-RISK"

        elif (
            profile.risk_score
            >= SUSPICIOUS_THRESHOLD
        ):

            profile.state = "SUSPICIOUS"

        elif (
            profile.risk_score
            >= 0.20
        ):

            profile.state = "DRIFTING"

        else:

            profile.state = "NORMAL"

        # ----------------------------------------------------
        # STEP 5
        # Update trust
        # ----------------------------------------------------

        self.update_trust(
            profile,
            risk
        )

        # ----------------------------------------------------
        # STEP 6
        # Adaptation Gate
        # ----------------------------------------------------

        allowed, gate_reason = (
            self.adaptation_gate(
                profile,
                activity,
                risk
            )
        )

        # ----------------------------------------------------
        # STEP 7
        # Decide whether baseline can change
        # ----------------------------------------------------

        if allowed:

            self.commit_to_baseline(
                profile,
                activity
            )

        else:

            profile.blocked_baseline_updates += 1

            # A blocked suspicious behavior is treated
            # as a potential poisoning attempt.

            if risk >= SUSPICIOUS_THRESHOLD:

                profile.poisoning_attempts += 1

        # ----------------------------------------------------
        # FINAL RESULT
        # ----------------------------------------------------

        result = {

            "identity":
                profile.identity,

            "resource":
                activity.resource,

            "action":
                activity.action,

            "risk":
                round(
                    risk,
                    3
                ),

            "cumulative_risk":
                round(
                    profile.risk_score,
                    3
                ),

            "trust_score":
                round(
                    profile.trust_score,
                    2
                ),

            "state":
                profile.state,

            "baseline_update":
                "ALLOWED"
                if allowed
                else "BLOCKED",

            "gate_reason":
                gate_reason,

            "reasons":
                reasons,

            "stable_resource_count":
                len(
                    profile.stable_resources
                ),

            "shadow_resource_count":
                len(
                    profile.shadow_resources
                ),

            "poisoning_attempts":
                profile.poisoning_attempts
        }

        profile.decision_history.append(
            result
        )

        return result

    # ========================================================
    # SECURITY REPORT
    # ========================================================

    def security_report(
        self,
        identity
    ):

        profile = self.get_profile(
            identity
        )

        return {

            "identity":
                identity,

            "state":
                profile.state,

            "trust_score":
                round(
                    profile.trust_score,
                    2
                ),

            "cumulative_risk":
                round(
                    profile.risk_score,
                    3
                ),

            "stable_resources":
                list(
                    profile.stable_resources.keys()
                ),

            "shadow_resources":
                list(
                    profile.shadow_resources.keys()
                ),

            "approved_baseline_updates":
                profile.approved_baseline_updates,

            "blocked_baseline_updates":
                profile.blocked_baseline_updates,

            "poisoning_attempts_detected":
                profile.poisoning_attempts
        }


# ============================================================
# BASELINE POISONING ATTACK
# ============================================================

def poisoning_attack(identity):

    return [

        # -----------------------------------------------
        # Normal behavior
        # -----------------------------------------------

        Activity(
            identity,
            "payment-db",
            "READ",
            10
        ),

        Activity(
            identity,
            "payment-api",
            "WRITE",
            11
        ),

        # -----------------------------------------------
        # Attacker starts slowly
        # -----------------------------------------------

        Activity(
            identity,
            "analytics-api",
            "READ",
            12
        ),

        Activity(
            identity,
            "analytics-api",
            "READ",
            12
        ),

        # -----------------------------------------------
        # Attacker attempts to establish new behavior
        # -----------------------------------------------

        Activity(
            identity,
            "analytics-api",
            "QUERY",
            13
        ),

        Activity(
            identity,
            "analytics-api",
            "QUERY",
            13
        ),

        # -----------------------------------------------
        # Attack moves toward sensitive resources
        # -----------------------------------------------

        Activity(
            identity,
            "credential-store",
            "READ",
            14
        ),

        Activity(
            identity,
            "credential-store",
            "READ",
            14
        ),

        Activity(
            identity,
            "credential-store",
            "EXPORT",
            14
        ),

        Activity(
            identity,
            "secret-vault",
            "EXPORT",
            15
        )
    ]


# ============================================================
# PRINT DEMO
# ============================================================

def print_demo(results):

    print()
    print("=" * 110)
    print(
        "SHADOWTRUST - BASELINE POISONING RESISTANCE"
    )
    print("=" * 110)

    print(
        f"{'Event':<8}"
        f"{'Resource':<22}"
        f"{'Action':<18}"
        f"{'Risk':<10}"
        f"{'State':<15}"
        f"{'Trust':<10}"
        f"{'Baseline':<12}"
    )

    print("-" * 110)

    for index, result in enumerate(
        results,
        start=1
    ):

        print(
            f"{index:<8}"
            f"{result['resource']:<22}"
            f"{result['action']:<18}"
            f"{result['risk']:<10}"
            f"{result['state']:<15}"
            f"{result['trust_score']:<10}"
            f"{result['baseline_update']:<12}"
        )

        if result["reasons"]:

            print(
                " " * 8 +
                "Reason: " +
                "; ".join(
                    result["reasons"]
                )
            )

        print(
            " " * 8 +
            result["gate_reason"]
        )

    print("=" * 110)


# ============================================================
# MAIN DEMO
# ============================================================

def main():

    engine = BaselineProtection()

    identity = "payment-service"

    # --------------------------------------------------------
    # Establish legitimate baseline
    # --------------------------------------------------------

    baseline = [

        Activity(
            identity,
            "payment-db",
            "READ",
            10
        ),

        Activity(
            identity,
            "payment-api",
            "WRITE",
            11
        ),

        Activity(
            identity,
            "logging-service",
            "WRITE",
            12
        )
    ]

    engine.establish_baseline(
        identity,
        baseline
    )

    print()
    print(
        "INITIAL TRUSTED BASELINE:"
    )

    print(
        engine.security_report(
            identity
        )
    )

    # --------------------------------------------------------
    # Run poisoning attack
    # --------------------------------------------------------

    attack = poisoning_attack(
        identity
    )

    results = []

    for activity in attack:

        result = engine.process(
            activity
        )

        results.append(result)

    print_demo(
        results
    )

    # --------------------------------------------------------
    # Final security report
    # --------------------------------------------------------

    print()
    print(
        "FINAL SECURITY REPORT"
    )

    print("-" * 50)

    report = engine.security_report(
        identity
    )

    for key, value in report.items():

        print(
            f"{key}: {value}"
        )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()