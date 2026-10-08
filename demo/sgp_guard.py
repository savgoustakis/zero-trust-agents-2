# =================================================================
#            sgp_guard.py (TypeSafe Jev Integration)
# Enforces natural-language enterprise business policies at runtime
# using Jev's System One intent and parameter evaluation.
# =================================================================

import json
import time
import re
from typing import Dict, Any, List, Optional

# Track if TypeSafe SDK is present
try:
    from typesafe_sdk import TypeSafeClient
    HAS_TYPESAFE = True
except ImportError:
    HAS_TYPESAFE = False


class SGPPolicy:
    """Represents a Natural-Language Semantic Governance Policy."""
    def __init__(self, name: str, target_tools: List[str], constraints: str, enforcement: str = "BLOCK", target_agent: str = "support-refund-agent"):
        self.name = name
        self.target_agent = target_agent
        self.target_tools = target_tools
        self.constraints = constraints
        self.enforcement = enforcement

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "target_agent": self.target_agent,
            "target_tools": self.target_tools,
            "constraints": self.constraints,
            "enforcement": self.enforcement
        }


class SGPGuard:
    """
    In-Line Semantic Governance Policy Gate.
    Intercepts ADK tool calls and evaluates them using TypeSafe Jev.
    """

    def __init__(self):
        self.policies: Dict[str, SGPPolicy] = {}
        self.evaluation_history: List[Dict[str, Any]] = []
        self._load_baseline_policies()

    def _load_baseline_policies(self):
        """Initializes the baseline natural language policies."""
        # 1. Single refund cap policy
        self.register_policy(SGPPolicy(
            name="refund-policy-cap",
            target_tools=["issue_refund", "calculate_restocking_fee"],
            constraints="Any single refund approval for more than 149 USD must be denied and routed to a human manager. Approvals of 149 USD or less are allowed.",
            enforcement="BLOCK"
        ))

        # 2. Semantic Category Restrictions
        self.register_policy(SGPPolicy(
            name="refund-policy-category",
            target_tools=["issue_refund", "calculate_restocking_fee"],
            constraints=(
                "Refunds for opened digital goods, software licenses, or clearance items "
                "over 30 USD must be denied and routed to a human manager. "
                "Refunds for physical hardware accessories up to 149 USD are allowed."
            ),
            enforcement="BLOCK"
        ))

        # 3. Adaptive Multi-Turn Policy
        self.register_policy(SGPPolicy(
            name="refund-policy-single-order-limit",
            target_tools=["issue_refund"],
            constraints="Order cannot receive multiple approved refunds in the same session without manager authorization.",
            enforcement="BLOCK"
        ))

    def register_policy(self, policy: SGPPolicy):
        self.policies[policy.name] = policy

    def create_policy(self, name: str, target_tools: List[str], constraint: str = "", constraints: str = "", enforcement: str = "BLOCK", target_agent: str = "support-refund-agent") -> SGPPolicy:
        policy_constraint = constraint or constraints
        policy = SGPPolicy(
            name=name,
            target_agent=target_agent,
            target_tools=target_tools,
            constraints=policy_constraint,
            enforcement=enforcement
        )
        self.register_policy(policy)
        return policy

    def remove_policy(self, policy_name: str):
        if policy_name in self.policies:
            del self.policies[policy_name]

    def evaluate_tool_call(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        user_prompt: str,
        session_history: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """In-line evaluation of a proposed tool execution against all active policies."""
        start_time = time.time()
        session_history = session_history or []

        applicable_policies = [p for p in self.policies.values() if tool_name in p.target_tools]

        if not applicable_policies:
            return {
                "verdict": "ALLOWED",
                "tool_call": f"{tool_name}({json.dumps(tool_args)})",
                "policies_checked": [],
                "rationale": f"No active SGP policies target tool '{tool_name}'. Allowed by default.",
                "action_taken": "TOOL_EXECUTION_PERMITTED",
                "latency_ms": 1.0
            }

        # Evaluate against each applicable policy (Fail-Closed)
        for policy in applicable_policies:
            verdict, rationale, confidence = self._judge_policy(
                policy=policy,
                tool_name=tool_name,
                tool_args=tool_args,
                user_prompt=user_prompt,
                session_history=session_history
            )

            if verdict == "DENIED":
                latency_ms = round((time.time() - start_time) * 1000, 2)
                decision = {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "tool_call": f"{tool_name}({', '.join(f'{k}={repr(v)}' for k, v in tool_args.items())})",
                    "evaluation": {
                        "verdict": "DENIED",
                        "policy_violated": policy.name,
                        "confidence": confidence,
                        "rationale": rationale
                    },
                    "action_taken": "TOOL_EXECUTION_SUPPRESSED",
                    "latency_ms": max(latency_ms, 2.5)
                }
                self.evaluation_history.append(decision)
                return decision

        # All policies passed
        latency_ms = round((time.time() - start_time) * 1000, 2)
        decision = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool_call": f"{tool_name}({', '.join(f'{k}={repr(v)}' for k, v in tool_args.items())})",
            "evaluation": {
                "verdict": "ALLOWED",
                "policy_violated": None,
                "confidence": 0.99,
                "rationale": "Tool invocation complies with all active natural language semantic policies."
            },
            "action_taken": "TOOL_EXECUTION_PERMITTED",
            "latency_ms": max(latency_ms, 2.1)
        }
        self.evaluation_history.append(decision)
        return decision

    def _judge_policy(
        self,
        policy: SGPPolicy,
        tool_name: str,
        tool_args: Dict[str, Any],
        user_prompt: str,
        session_history: List[Dict[str, Any]]
    ) -> tuple[str, str, float]:
        """
        Evaluates policies using TypeSafe Jev system_one choices.
        """
        amount = float(tool_args.get("amount", tool_args.get("price", 0.0)))
        item = str(tool_args.get("item", ""))
        order_id = str(tool_args.get("order_id", ""))

        # Check if SDK is available
        if HAS_TYPESAFE:
            try:
                ts_client = TypeSafeClient()

                # -------------------------------------------------------------
                # 1. refund-policy-cap check via Jev
                # -------------------------------------------------------------
                if policy.name == "refund-policy-cap":
                    print(f"  \033[36m[SGP Jev]\033[0m Evaluating transaction limit for ${amount:.2f}...")
                    decision = ts_client.system_one(
                        state=f"Proposed refund amount: {amount}. Limit constraint: {policy.constraints}",
                        questions={
                            "limit_exceeded": {
                                "type": "choice",
                                "options": ["exceeded", "compliant"],
                                "criteria": {
                                    "exceeded": f"Choose this if the amount {amount} exceeds 149.00 USD.",
                                    "compliant": f"Choose this if the amount {amount} is 149.00 USD or less."
                                }
                            }
                        }
                    )
                    verdict = decision.choices["limit_exceeded"].choice
                    confidence = decision.choices["limit_exceeded"].confidence

                    if verdict == "exceeded":
                        return (
                            "DENIED",
                            f"Action denied. Requested single refund amount of ${amount:.2f} exceeds the policy cap of $149.00.",
                            confidence
                        )
                    return ("ALLOWED", "Amount is compliant with policy cap.", confidence)

                # -------------------------------------------------------------
                # 2. refund-policy-category check via Jev
                # -------------------------------------------------------------
                if policy.name == "refund-policy-category":
                    print(f"  \033[36m[SGP Jev]\033[0m Evaluating category mapping for '{item}'...")
                    decision = ts_client.system_one(
                        state=f"Item name: {item}. Proposed amount: {amount}. User requested: '{user_prompt}'",
                        questions={
                            "category": {
                                "type": "choice",
                                "options": ["digital_software", "hardware_accessory"],
                                "criteria": {
                                    "digital_software": "Choose this if the item is a software license, SaaS subscription, virtual key, workspace download, or digital item.",
                                    "hardware_accessory": "Choose this if the item is physical hardware, keyboard, mouse, dock, webcam, or accessory."
                                }
                            }
                        }
                    )
                    category = decision.choices["category"].choice
                    confidence = decision.choices["category"].confidence

                    if category == "digital_software" and amount > 30.00:
                        return (
                            "DENIED",
                            f"The tool attempted to refund ${amount:.2f} for '{item}', a digital software product. Digital software refunds over $30 require manager authorization.",
                            confidence
                        )
                    return ("ALLOWED", "Item category is compliant with policy constraints.", confidence)

                # -------------------------------------------------------------
                # 3. refund-policy-single-order-limit check via Jev
                # -------------------------------------------------------------
                if policy.name == "refund-policy-single-order-limit":
                    clean_order_id = str(order_id).replace("#", "").strip()
                    prior_approved = [
                        h for h in session_history
                        if (h.get("action") == "issue_refund" or h.get("tool_called") == "issue_refund")
                        and str(h.get("order_id", "")).replace("#", "").strip() == clean_order_id
                        and h.get("status") == "APPROVED"
                    ]

                    # Map prior state to Jev evaluation
                    has_prior = "yes" if len(prior_approved) > 0 else "no"
                    print(f"  \033[36m[SGP Jev]\033[0m Evaluating prior session history for Order #{order_id}...")
                    
                    decision = ts_client.system_one(
                        state=f"Order ID: {order_id}. Has prior approved refund in active session history?: {has_prior}",
                        questions={
                            "replay_attempt": {
                                "type": "choice",
                                "options": ["replay_detected", "safe"],
                                "criteria": {
                                    "replay_detected": f"Choose this if prior approved refund is 'yes'.",
                                    "safe": f"Choose this if prior approved refund is 'no'."
                                }
                            }
                        }
                    )
                    verdict = decision.choices["replay_attempt"].choice
                    confidence = decision.choices["replay_attempt"].confidence

                    if verdict == "replay_detected":
                        prior_sum = sum(float(r.get("turn_amount", r.get("amount", 0.0))) for r in prior_approved)
                        return (
                            "DENIED",
                            f"Action denied due to the 'refund-policy-single-order-limit' constraint. Order #{order_id} already received an approved refund in this session (Prior Approved: ${prior_sum:.2f}).",
                            confidence
                        )
                    return ("ALLOWED", "First refund request for this order in the active session.", confidence)

            except Exception as e:
                print(f"  \033[33m[SGP Jev Warning]\033[0m API failed ({e}). Falling back to static evaluation.")

        # =================================================================
        # 🛡️ LOCAL SECURE FALLBACK LOGIC (Used if Jev is unconfigured/offline)
        # =================================================================
        if policy.name == "refund-policy-cap":
            if amount > 149.00:
                return ("DENIED", f"Action denied. Requested single refund amount of ${amount:.2f} exceeds the policy cap of $149.00.", 0.99)
            return ("ALLOWED", "Amount is within single transaction limit.", 0.99)

        if policy.name == "refund-policy-category":
            digital_keywords = ["workplace", "license", "software", "ide", "digital", "download", "saas", "subscription", "clearance", "gift card"]
            is_digital = any(kw in item.lower() for kw in digital_keywords) or any(kw in user_prompt.lower() for kw in digital_keywords)
            if is_digital and amount > 30.00:
                return ("DENIED", f"The tool attempted to refund ${amount:.2f} for '{item}', a digital software product. Digital software refunds over $30 require manager authorization.", 0.98)
            return ("ALLOWED", "Category and amount comply with category constraints.", 0.96)

        if policy.name == "refund-policy-single-order-limit":
            clean_order_id = str(order_id).replace("#", "").strip()
            prior_approved = [
                h for h in session_history
                if (h.get("action") == "issue_refund" or h.get("tool_called") == "issue_refund")
                and str(h.get("order_id", "")).replace("#", "").strip() == clean_order_id
                and h.get("status") == "APPROVED"
            ]
            if len(prior_approved) > 0:
                prior_sum = sum(float(r.get("turn_amount", r.get("amount", 0.0))) for r in prior_approved)
                return ("DENIED", f"Action denied due to the 'refund-policy-single-order-limit' constraint. Order #{order_id} already received an approved refund in this session (Prior Approved: ${prior_sum:.2f}).", 0.99)
            return ("ALLOWED", f"First refund request for order #{order_id} in session.", 0.97)

        return ("ALLOWED", "Compliant with policy constraints.", 0.90)


if __name__ == "__main__":
    # Test suite
    sgp = SGPGuard()
    print("=== Testing Semantic Governance Policies (SGP) via TypeSafe Jev ===")
    
    # Test 1: $120 Software License Refund (Act 2)
    t1_args = {"order_id": "99281", "amount": 120.00, "item": "Workplace User License"}
    t1_prompt = "I purchased an annual Workplace user license ($120.00) under order #99281. The tool did not fit our workflow, so please issue a full refund to my card."
    res1 = sgp.evaluate_tool_call("issue_refund", t1_args, t1_prompt)
    print(f"\nTest 1 (Software License > $30):\n{json.dumps(res1, indent=2)}")

    # Test 2: $20 Physical Cable (Act 3 Turn 1)
    t2_args = {"order_id": "99281", "amount": 20.00, "item": "Replacement Power Cable"}
    t2_prompt = "Order #99281 was missing the power cable ($20 value). Please refund $20."
    res2 = sgp.evaluate_tool_call("issue_refund", t2_args, t2_prompt)
    print(f"\nTest 2 (Physical Accessory $20):\n{json.dumps(res2, indent=2)}")
