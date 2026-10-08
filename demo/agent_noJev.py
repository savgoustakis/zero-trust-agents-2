# =================================================================
#            START OF THE COMPLETE agent.py FILE
# =================================================================

import json
import time
import re
from typing import Dict, Any, List
import uuid

# --- Import Cloud Libraries ---
from model_armor import ModelArmorGuard
from sgp_guard import SGPGuard
from aad_engine import AADTelemetryEngine
from db_guard import sign_transaction_payload
from google.cloud import bigquery

# --- Modern Storage Write API Imports ---
from google.cloud import bigquery_storage_v1
from google.cloud.bigquery_storage_v1 import writer
from google.cloud.bigquery_storage_v1 import types
from google.protobuf import descriptor_pb2
from typesafe import TypeSafeClient  # Import the official TypeSafe SDK


# =================================================================
#                         TOOL DEFINITIONS
# =================================================================

bq_client = bigquery.Client()

def check_already_refunded(order_id: str) -> bool:
    """
    Queries the secure ledger to determine if this order has already
    been refunded.
    """
    clean_id = str(order_id).strip()
    table_id = "zerotrust-svcsproject00-mngmnt.agent_orders.secure_ledger"
    
    print(f"\033[34m[ADK Check: Double-Refund]\033[0m Auditing secure ledger for existing refunds on Order #{clean_id}...")
    
    query = f"""
        SELECT COUNT(*) as count 
        FROM `{table_id}` 
        WHERE order_id = @order_id
    """
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
    clean_id = str(order_id).strip()
    table_id = "zerotrust-svcsproject00-mngmnt.agent_orders.orders"
    print(f"\033[34m[ADK Tool: verify_order]\033[0m Querying BigQuery for order #{clean_id}...")
    query = f"SELECT * FROM `{table_id}` WHERE order_id = @order_id LIMIT 1"
    job_config = bigquery.QueryJobConfig(query_parameters=[bigquery.ScalarQueryParameter("order_id", "STRING", clean_id)])
    try:
        # --- FIXED SYNTAX HERE ---
        results = [dict(row) for row in bq_client.query(query, job_config=job_config)]
        if not results:
            print(f"\033[91m[ADK Tool: verify_order]\033[0m Order #{clean_id} not found.")
            return {"error": f"Order #{order_id} not found."}
        order_data = results[0]
        if order_data.get('items'): order_data['items'] = [dict(item) for item in order_data['items']]
        print(f"\033[34m[ADK Tool: verify_order]\033[0m Found order #{clean_id}. Total: ${order_data.get('total_amount', 0):.2f}")
        return order_data
    except Exception as e:
        print(f"\033[91m[BigQuery Error]\033[0m Failed to query: {e}")
        return {"error": f"DB error for order #{order_id}."}


def get_proto_type_from_bq_type(bq_type: str) -> int:
    """Maps BigQuery field types to Protobuf field types."""
    mapping = {
        "STRING": 9,  # TYPE_STRING
        "INTEGER": 3, # TYPE_INT64
        "FLOAT": 1,   # TYPE_DOUBLE
        "BOOLEAN": 8, # TYPE_BOOL
    }
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
    """
    Authorizes a payout, signs it with KMS, and submits it to the
    BigQuery transaction_pipeline table using the modern Storage Write API.
    """
    agent_id = "support-refund-agent"
    payload = {
        "agent_id": agent_id, "action": "issue_refund", "details": {"order_id": order_id, "amount": amount, "item": item, "recipient": recipient},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    sig = sign_transaction_payload(agent_id, payload)
    
    # Define table paths
    project_id = "zerotrust-svcsproject00-mngmnt"
    dataset_id = "agent_orders"
    table_id = "transaction_pipeline"
    
    print(f"\033[34m[ADK Tool: issue_refund]\033[0m Initializing BigQuery Storage Write API...")
    write_client = bigquery_storage_v1.BigQueryWriteClient()
    parent = write_client.table_path(project_id, dataset_id, table_id)
    write_stream_path = f"{parent}/_default"
    
    row_to_insert = {
        "signature": sig,
        "payload": json.dumps(payload)
    }

    try:
        append_rows_request = types.AppendRowsRequest()
        append_rows_request.write_stream = write_stream_path
        
        serialized_row = json.dumps(row_to_insert).encode("utf-8")
        
        proto_rows = types.ProtoRows()
        proto_rows.serialized_rows.append(serialized_row)
        
        proto_data = types.AppendRowsRequest.ProtoData()
        proto_data.rows = proto_rows
        
        table_ref = bq_client.get_table(f"{project_id}.{dataset_id}.{table_id}")
        proto_descriptor = build_dynamic_proto_descriptor(table_ref)
        
        proto_schema = types.ProtoSchema()
        proto_schema.proto_descriptor = proto_descriptor
        
        proto_data.writer_schema = proto_schema
        append_rows_request.proto_rows = proto_data

        print(f"\033[34m[ADK Tool: issue_refund]\033[0m Streaming transaction via Storage Write API...")
        write_client.append_rows(requests=[append_rows_request])
        
        print(f"\033[34m[ADK Tool: issue_refund]\033[0m KMS Signature generated: {sig[:16]}...")
        print(f"\033[34m[ADK Tool: issue_refund]\033[0m Transaction successfully committed to Storage Write stream.")

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
        
        if order_id_match:
            found_order_id = order_id_match.group(1)
            if "refund" in prompt_lower:
                
                # --- NEW DOUBLE REFUND CHECK ---
                if check_already_refunded(found_order_id):
                    return "already_refunded", {"order_id": found_order_id}
                # -------------------------------
                
                order_details = verify_order(found_order_id)
                if not order_details or "error" in order_details:
                    return "issue_refund", {"order_id": found_order_id, "amount": 0.0, "item": "Order Not Found", "recipient": "unknown"}
                return "issue_refund", {"order_id": found_order_id, "amount": order_details.get("total_amount", 0.0), "item": "Full Order Refund", "recipient": order_details.get("customer_id", "unknown")}
            return "verify_order", {"order_id": found_order_id}
        
        if "workplace" in prompt_lower: return "issue_refund", {"order_id": "99281", "amount": 120.00, "item": "Workplace User License", "recipient": "cust_402"}
        if "20" in prompt_lower: return "issue_refund", {"order_id": "99281", "amount": 20.00, "item": "Accessory", "recipient": "cust_402"}
        if "restocking" in prompt_lower: return "calculate_restocking_fee", {"price": 149.00, "condition": "opened"}
        
        print("\033[93m[Agent Plan]\033[0m No matching keywords or order ID found. Falling back to default.")
        return "issue_refund", {"order_id": "99281", "amount": 149.00, "item": "Default Bundle", "recipient": "cust_402"}

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
            errors = bq_client.insert_rows_json(history_table_id, [row_to_insert])
            if not errors: print(f"\033[34m[History]\033[0m Turn {self.turn_id} logged to BigQuery.")
            else: print(f"\033[91m[BigQuery Error]\033[0m Could not write to session_history: {errors}")
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
        
        # --- DOUBLE-REFUND DETERMINISTIC ENFORCEMENT ---
        if planned_tool == "already_refunded":
            raw_response = f"This order (Order #{tool_args['order_id']}) has already been refunded. Please contact customer support for further assistance."
            scrubbed_resp, redactions = self.model_armor.scrub_egress(raw_response)
            print(f"🛡️ [DOUBLE-REFUND BLOCK] Suppressing tool execution. {scrubbed_resp}\n")
            self._log_turn_history(user_prompt, "already_refunded", tool_args, "BLOCKED_BY_DOUBLE_REFUND", 0.0)
            return
        # ---------------------------------------------------

        print(f"[{self.agent_id} Plan] Prepared tool: {planned_tool}({tool_args})")
        
        print("\n[Stage 3: SGP Gate] Evaluating proposed tool call...")
        sgp_decision = self.sgp_guard.evaluate_tool_call(planned_tool, tool_args, user_prompt, self.session_history)
        if sgp_decision["evaluation"]["verdict"] == "DENIED":
            print(f"🛡️ [SGP INTERCEPT] Execution suppressed: {sgp_decision['evaluation']['rationale']}")
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
