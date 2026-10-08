# =================================================================
#            START OF THE COMPLETE agent.py FILE
# =================================================================

import json
import time
import re
import uuid
import hashlib
import base64
import binascii
from typing import Dict, Any, List

# --- Import Cloud & Crypto Libraries ---
from model_armor import ModelArmorGuard
from sgp_guard import SGPGuard
from aad_engine import AADTelemetryEngine
from db_guard import sign_transaction_payload
from google.cloud import bigquery
from google.cloud import kms
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# --- Modern Storage Write API Imports ---
from google.cloud import bigquery_storage_v1
from google.cloud.bigquery_storage_v1 import writer
from google.cloud.bigquery_storage_v1 import types
from google.protobuf import descriptor_pb2

# =================================================================
#                         TOOL DEFINITIONS
# =================================================================

bq_client = bigquery.Client()

def check_already_refunded(order_id: str) -> bool:
    """Queries the secure ledger to determine if this order was already refunded."""
    clean_id = str(order_id).strip()
    table_id = "zerotrust-svcsproject00-mngmnt.agent_orders.secure_ledger"
    
    print(f"\033[34m[ADK Check: Double-Refund]\033[0m Auditing secure ledger for existing refunds on Order #{clean_id}...")
    
    query = f"SELECT COUNT(*) as count FROM `{table_id}` WHERE order_id = @order_id"
    job_config = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("order_id", "STRING", clean_id)]
    )
    
    try:
        results = list(bq_client.query(query, job_config=job_config))
        if results and results[0]['count'] > 0:
            return True
    except Exception as e:
        print(f"\033[91m[BigQuery Error]\033[0m Failed to query secure ledger: {e}")
        
    return False

def verify_order(order_id: str) -> dict:
    """Fetches the raw order details directly from the BigQuery operational table."""
    clean_id = str(order_id).strip()
    table_id = "zerotrust-svcsproject00-mngmnt.agent_orders.orders"
    print(f"\033[34m[ADK Tool: verify_order]\033[0m Querying BigQuery for order #{clean_id}...")
    
    query = f"SELECT * FROM `{table_id}` WHERE order_id = @order_id LIMIT 1"
    job_config = bigquery.QueryJobConfig(query_parameters=[bigquery.ScalarQueryParameter("order_id", "STRING", clean_id)])
    
    try:
        results = [dict(row) for row in bq_client.query(query, job_config=job_config)]
        if not results:
            print(f"\033[91m[ADK Tool: verify_order]\033[0m Order #{clean_id} not found.")
            return {"error": f"Order #{order_id} not found."}
        
        order_data = results[0]
        if order_data.get('items'): 
            order_data['items'] = [dict(item) for item in order_data['items']]
        print(f"\033[34m[ADK Tool: verify_order]\033[0m Found order #{clean_id}. Total: ${order_data.get('total_amount', 0):.2f}")
        return order_data
    except Exception as e:
        print(f"\033[91m[BigQuery Error]\033[0m Failed to query: {e}")
        return {"error": f"DB error for order #{order_id}."}


ORDER_SIGNING_KEY_PATH = "projects/zerotrust-svcsproject00-mngmnt/locations/global/keyRings/zerotrust-agent-keyring/cryptoKeys/zerotrust-agent-ordersigning-key01/cryptoKeyVersions/1"
EXPECTED_SIGNING_ALGORITHM = "RSA_SIGN_PSS_2048_SHA256"
_ORDER_PUBLIC_KEY = None  # Cached after the first successful fetch


def _get_order_public_key():
    """
    Fetches (once) and caches the order-signing public key from Cloud KMS.

    Raises on any failure: if we cannot obtain the trusted public key we
    cannot verify anything, so the caller must fail closed.
    """
    global _ORDER_PUBLIC_KEY
    if _ORDER_PUBLIC_KEY is None:
        kms_client = kms.KeyManagementServiceClient()
        pub = kms_client.get_public_key(name=ORDER_SIGNING_KEY_PATH)
        # Pin the algorithm so a key-version swap can't silently change the scheme.
        if pub.algorithm.name != EXPECTED_SIGNING_ALGORITHM:
            raise ValueError(f"Unexpected KMS key algorithm {pub.algorithm.name}; expected {EXPECTED_SIGNING_ALGORITHM}")
        _ORDER_PUBLIC_KEY = load_pem_public_key(pub.pem.encode("utf-8"))
    return _ORDER_PUBLIC_KEY


def verify_order_integrity(order_data: dict) -> bool:
    """
    Cryptographically verifies the order's KMS signature to ensure the
    database row hasn't been tampered with post-purchase.

    FAIL-CLOSED: the ONLY accepted proof is an RSA-PSS signature that
    verifies against the KMS order-signing public key. There is no
    symmetric/HMAC fallback - a fallback whose key ships in the repo would
    let anyone forge "authentic" orders (downgrade attack). If KMS is
    unreachable, verification fails and the refund is blocked.
    """
    print(f"\033[34m[ADK Check: Data Integrity]\033[0m Cryptographically verifying Order #{order_data.get('order_id')}...")

    signature_b64 = order_data.get('signature')
    if not signature_b64:
        print(f"\033[91m🚨 [SECURITY VIOLATION]\033[0m Missing signature detected!")
        return False

    # 1. Reconstruct the clean payload exactly as it was when purchased
    payload = {
        "order_id": order_data.get("order_id"),
        "customer_id": order_data.get("customer_id"),
        "total_amount": float(order_data.get("total_amount", 0.0)),
        "items": order_data.get("items", [])
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

    # 2. Decode the signature - anything that isn't valid base64 (garbage strings,
    #    hex HMACs, "ROGUE_..." values) is rejected here.
    try:
        sig_bytes = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        print(f"\033[91m🚨 [SECURITY VIOLATION]\033[0m Malformed signature (not a KMS RSA signature)!")
        return False

    # 3. Obtain the trusted public key - fail closed if KMS is unavailable
    try:
        public_key = _get_order_public_key()
    except Exception as e:
        print(f"\033[91m🚨 [INTEGRITY CHECK UNAVAILABLE]\033[0m Cannot fetch KMS public key ({e}). Failing closed.")
        return False

    # 4. Strict RSA-PSS / SHA-256 verification (matches KMS RSA_SIGN_PSS_2048_SHA256)
    try:
        public_key.verify(
            sig_bytes,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32  # SHA-256 digest length, as used by Cloud KMS
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        print(f"\033[91m🚨 [SECURITY VIOLATION DETECTED]\033[0m Signature does not match payload "
              f"(tampered row or signed by an unauthorized key)!")
        return False

    print(f"\033[32m✓ Signature VERIFIED (KMS RSA-PSS 2048). Payload is authentic.\033[0m")
    return True


def get_proto_type_from_bq_type(bq_type: str) -> int:
    """Maps BigQuery field types to Protobuf field types."""
    mapping = {"STRING": 9, "INTEGER": 3, "FLOAT": 1, "BOOLEAN": 8}
    return mapping.get(bq_type, 9)

def build_dynamic_proto_descriptor(table_ref) -> descriptor_pb2.DescriptorProto:
    """Generates a dynamic Protobuf Descriptor from a BigQuery Table."""
    descriptor = descriptor_pb2.DescriptorProto()
    descriptor.name = "TransactionRow"
    for i, field in enumerate(table_ref.schema):
        field_proto = descriptor_pb2.FieldDescriptorProto()
        field_proto.name = field.name
        field_proto.number = i + 1
        field_proto.label = 1 # LABEL_OPTIONAL
        field_proto.type = get_proto_type_from_bq_type(field.field_type)
        descriptor.field.append(field_proto)
    return descriptor


def issue_refund(order_id: str, amount: float, item: str, recipient: str = "cust_402") -> str:
    """Authorizes a payout, signs it with KMS, and submits it to BigQuery."""
    agent_id = "support-refund-agent"
    payload = {
        "agent_id": agent_id, 
        "action": "issue_refund", 
        "details": {"order_id": order_id, "amount": amount, "item": item, "recipient": recipient},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    sig = sign_transaction_payload(agent_id, payload)
    
    project_id = "zerotrust-svcsproject00-mngmnt"
    dataset_id = "agent_orders"
    table_id = "transaction_pipeline"
    
    print(f"\033[34m[ADK Tool: issue_refund]\033[0m Initializing BigQuery Storage Write API...")
    write_client = bigquery_storage_v1.BigQueryWriteClient()
    parent = write_client.table_path(project_id, dataset_id, table_id)
    write_stream_path = f"{parent}/_default"
    
    try:
        desc_proto = descriptor_pb2.DescriptorProto()
        desc_proto.name = "TransactionRow"
        desc_proto.field.add(name="signature", number=1, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING, label=1)
        desc_proto.field.add(name="payload", number=2, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING, label=1)
        
        file_proto = descriptor_pb2.FileDescriptorProto(name=f"dynamic_schema_{uuid.uuid4().hex}.proto")
        file_proto.message_type.append(desc_proto)
        
        from google.protobuf import descriptor_pool, message_factory
        pool = descriptor_pool.DescriptorPool()
        pool.Add(file_proto)
        MessageClass = message_factory.GetMessageClass(pool.FindMessageTypeByName("TransactionRow"))
        
        msg = MessageClass(signature=sig, payload=json.dumps(payload))
        serialized_bytes = msg.SerializeToString()
        
        proto_schema = types.ProtoSchema(proto_descriptor=desc_proto)
        proto_data_template = types.AppendRowsRequest.ProtoData(writer_schema=proto_schema)
        request_template = types.AppendRowsRequest(write_stream=write_stream_path, proto_rows=proto_data_template)
        
        print(f"\033[34m[ADK Tool: issue_refund]\033[0m Establishing gRPC connection...")
        append_stream = writer.AppendRowsStream(write_client, request_template)
        
        print(f"\033[34m[ADK Tool: issue_refund]\033[0m Streaming transaction payload...")
        proto_rows = types.ProtoRows(serialized_rows=[serialized_bytes])
        proto_data_payload = types.AppendRowsRequest.ProtoData(rows=proto_rows)
        append_request = types.AppendRowsRequest(proto_rows=proto_data_payload)
        
        future = append_stream.send(append_request)
        future.result() 
        append_stream.close()
        
        print(f"\033[34m[ADK Tool: issue_refund]\033[0m KMS Signature generated: {sig[:16]}...")
        print(f"\033[34m[ADK Tool: issue_refund]\033[0m Transaction successfully committed to Storage Write Stream.")
    except Exception as e:
        print(f"\033[91m[Storage Write API Error]\033[0m Failed to stream rows: {e}")
        
    return sig


def calculate_restocking_fee(price: float, condition: str = "opened", days_overdue: int = 0) -> float:
    print(f"\033[34m[ADK Tool: calculate_restocking_fee]\033[0m Calculating fee for item price ${price:.2f}.")
    return price * 0.15


# =================================================================
#                     AGENT RUNTIME ORCHESTRATOR
# =================================================================

class SupportRefundRuntime:
    def __init__(self, session_id: str):
        self.agent_id = "support-refund-agent"
        self.session_id = session_id
        self.turn_id = 0
        self.model_armor = ModelArmorGuard(sensitivity="HIGH")
        self.sgp_guard = SGPGuard()
        self.aad_engine = AADTelemetryEngine()
        self.session_history = []

    def _plan_tool_invocation(self, prompt: str) -> tuple[str, Dict[str, Any]]:
        prompt_lower = prompt.lower()
        order_id_match = re.search(r'(\b\d{4,8}\b)', prompt)
        found_order_id = order_id_match.group(1) if order_id_match else None

        chosen_tool = "ignore"
        try:
            from typesafe_sdk import TypeSafeClient  
            ts_client = TypeSafeClient()
            print(f"\033[36m[TypeSafe Jev]\033[0m Evaluating user intent...")
            intent_decision = ts_client.system_one(
                state=prompt,
                questions={
                    "tool_choice": {
                        "type": "choice",
                        "options": ["issue_refund", "verify_order", "calculate_restocking_fee", "ignore"],
                        "criteria": {
                            "issue_refund": "Choose this if the user wants money back, credit, or a refund.",
                            "verify_order": "Choose this if the user wants to check an order status or view details.",
                            "calculate_restocking_fee": "Choose this if the user wants to calculate return fees or restocking rules.",
                            "ignore": "Choose this if the request is unrelated or invalid."
                        }
                    }
                }
            )
            chosen_tool = intent_decision.choices["tool_choice"].choice
            confidence = intent_decision.choices["tool_choice"].confidence
            print(f"\033[36m[TypeSafe Jev]\033[0m Intent resolved to: '{chosen_tool}' ({confidence*100:.1f}% confidence).")
            
        except Exception as e:
            print(f"\033[33m[TypeSafe Jev]\033[0m Fallback mode triggered: {e}")
            if "refund" in prompt_lower or "20" in prompt_lower or "workplace" in prompt_lower:
                chosen_tool = "issue_refund"
            elif "restocking" in prompt_lower:
                chosen_tool = "calculate_restocking_fee"
            elif found_order_id:
                chosen_tool = "verify_order"

        # -----------------------------------------------------------------
        # STRUCTURED ROUTING BASED ON CHOICE
        # -----------------------------------------------------------------
        if chosen_tool == "issue_refund":
            if found_order_id:
                # 1. Block Replays
                if check_already_refunded(found_order_id):
                    return "already_refunded", {"order_id": found_order_id}
                
                # 2. Fetch Data
                order_details = verify_order(found_order_id)
                if not order_details or "error" in order_details:
                    return "issue_refund", {"order_id": found_order_id, "amount": 0.0, "item": "Order Not Found", "recipient": "unknown"}
                
                # 3. Validate Database Row Integrity!
                if not verify_order_integrity(order_details):
                    return "tampered_order", {"order_id": found_order_id}
                
                return "issue_refund", {
                    "order_id": found_order_id, 
                    "amount": order_details.get("total_amount", 0.0), 
                    "item": "Full Order Refund", 
                    "recipient": order_details.get("customer_id", "unknown")
                }
            else:
                if "workplace" in prompt_lower: return "issue_refund", {"order_id": "99281", "amount": 120.00, "item": "Workplace User License", "recipient": "cust_402"}
                if "20" in prompt_lower: return "issue_refund", {"order_id": "99281", "amount": 20.00, "item": "Accessory", "recipient": "cust_402"}
                print("\033[93m[Agent Plan]\033[0m Missing explicit parameters. Raising fallback alert.")
                return "unclassified_intent", {}

        elif chosen_tool == "verify_order" and found_order_id:
            return "verify_order", {"order_id": found_order_id}

        elif chosen_tool == "calculate_restocking_fee":
            price_match = re.search(r'\$(\d+)', prompt)
            price = float(price_match.group(1)) if price_match else 149.00
            return "calculate_restocking_fee", {"price": price, "condition": "opened"}

        print("\033[93m[Agent Plan]\033[0m Intent unclassified or ignored. Triggering fallback error.")
        return "unclassified_intent", {}


    def _log_turn_history(self, user_prompt, tool_name, tool_args, status, amount):
        if status == "APPROVED":
            history_entry = {**tool_args, "turn": self.turn_id, "tool_called": tool_name, "status": "APPROVED", "turn_amount": amount}
            self.session_history.append(history_entry)
        history_table_id = "zerotrust-svcsproject00-mngmnt.agent_orders.session_history"
        row_to_insert = {
            "session_id": self.session_id, "turn_id": self.turn_id, "order_id": tool_args.get("order_id"),
            "tool_called": tool_name, "status": status, "turn_amount": amount,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        }
        try:
            bq_client.insert_rows_json(history_table_id, [row_to_insert])
        except Exception as e:
            print(f"\033[91m[BigQuery Error]\033[0m Exception while writing to session_history: {e}")


    def process_turn(self, user_prompt: str):
        self.turn_id += 1
        print(f"\n========================= CONVERSATION TURN {self.turn_id} =========================")
        print(f'User Prompt: "{user_prompt}"\n')
        
        print("[Stage 1: Model Armor] Screening prompt...")
        armor_ingress = self.model_armor.inspect_ingress(user_prompt)
        if armor_ingress["action"] == "BLOCK":
            print(f"🛡️ [MODEL ARMOR INTERCEPT] Ingress blocked: {armor_ingress.get('findings', ['Reason not specified.'])[0]}")
            self._log_turn_history(user_prompt, "N/A", {}, "BLOCKED_BY_MODEL_ARMOR", 0.0)
            return
        print(f"✓ [Stage 1: Model Armor] Prompt clean.\n")

        print(f"[{self.agent_id} Reasoning] Analyzing request...")
        planned_tool, tool_args = self._plan_tool_invocation(user_prompt)
        
        # --- PRE-EXECUTION BLOCKS ---
        if planned_tool == "unclassified_intent":
            raw_response = "Sorry - our system can not process your request - contact our Customer Service team"
            scrubbed_resp, redactions = self.model_armor.scrub_egress(raw_response)
            print(f"\033[31m🛡️ [FALLBACK EXECUTED]\033[0m {scrubbed_resp}\n")
            self._log_turn_history(user_prompt, "unclassified_intent", {}, "BLOCKED_BY_FALLBACK", 0.0)
            return

        if planned_tool == "already_refunded":
            raw_response = f"This order (Order #{tool_args['order_id']}) has already been refunded. Please contact customer support for further assistance."
            scrubbed_resp, redactions = self.model_armor.scrub_egress(raw_response)
            print(f"\033[31m🛡️ [DOUBLE-REFUND BLOCK]\033[0m Suppressing tool execution. {scrubbed_resp}\n")
            self._log_turn_history(user_prompt, "already_refunded", tool_args, "BLOCKED_BY_DOUBLE_REFUND", 0.0)
            return

        if planned_tool == "tampered_order":
            raw_response = f"Security Alert: Order #{tool_args['order_id']} failed cryptographic integrity verification. This incident has been logged."
            scrubbed_resp, redactions = self.model_armor.scrub_egress(raw_response)
            print(f"\033[31m🛡️ [INTEGRITY BLOCK]\033[0m Suppressing tool execution. {scrubbed_resp}\n")
            self._log_turn_history(user_prompt, "tampered_order", tool_args, "BLOCKED_BY_INTEGRITY_CHECK", 0.0)
            return

        print(f"[{self.agent_id} Plan] Prepared tool: {planned_tool}({tool_args})")
        
        print("\n[Stage 3: SGP Gate] Evaluating proposed tool call...")
        sgp_decision = self.sgp_guard.evaluate_tool_call(planned_tool, tool_args, user_prompt, self.session_history)
        verdict = sgp_decision.get("evaluation", {}).get("verdict")
        rationale = sgp_decision.get("evaluation", {}).get("rationale", "No policy rationale provided.")
        if not verdict:
            verdict = sgp_decision.get("verdict", "APPROVED")
            rationale = sgp_decision.get("rationale", "No policy rationale provided.")
            
        if verdict == "DENIED":
            print(f"🛡️ [SGP INTERCEPT] Execution suppressed: {rationale}")
            self._log_turn_history(user_prompt, planned_tool, tool_args, "BLOCKED_BY_SGP", tool_args.get("amount", 0.0))
            return

        print(f"✓ [Stage 3: SGP Gate] Complies with policies. Executing...\n")

        kms_sig, tool_output = None, None
        if planned_tool == "issue_refund": kms_sig = issue_refund(**tool_args)
        elif planned_tool == "calculate_restocking_fee": tool_output = calculate_restocking_fee(**tool_args)
        elif planned_tool == "verify_order": tool_output = verify_order(**tool_args)

        if kms_sig: raw_response = f"Refund for ${tool_args.get('amount', 0.0):.2f} on Order #{tool_args.get('order_id', '')} authorized. Receipt: {kms_sig}"
        elif tool_output: raw_response = f"Tool '{planned_tool}' result: {json.dumps(tool_output)}"
        else: raw_response = f"Tool '{planned_tool}' executed."
            
        scrubbed_resp, redactions = self.model_armor.scrub_egress(raw_response)
        print(f"[{self.agent_id} Response] {scrubbed_resp}\n")
        
        self._log_turn_history(user_prompt, planned_tool, tool_args, "APPROVED", tool_args.get("amount", 0.0))
        return

# =================================================================
#                         MAIN EXECUTION LOOP
# =================================================================

def main():
    session_id = f"sess_{str(uuid.uuid4())[:8]}"
    runtime = SupportRefundRuntime(session_id=session_id)
    print("★ Initialized Customer Support & Returns Agent ('support-refund-agent') on Gemini Enterprise Agent Platform ★")
    print(f"   Session ID: {session_id}")
    print("   Enter your prompt below. Type 'exit' or 'quit' to end the session.")
    while True:
        try:
            user_prompt = input("\nEnter your prompt > ")
            if user_prompt.strip().lower() in ["exit", "quit"]: break
            if not user_prompt.strip(): continue
            runtime.process_turn(user_prompt)
        except (KeyboardInterrupt, EOFError): break
    print("\nExiting agent session. Goodbye!")

if __name__ == "__main__":
    main()

# =================================================================
#                     END OF COMPLETE agent.py FILE
# =================================================================