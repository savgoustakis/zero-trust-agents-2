# =================================================================
#            START OF THE COMPLETE db_guard.py FILE
# =================================================================

import json
import time
import sys
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
import hmac as hmac_compare
from google.cloud import bigquery

# --- Terminal ANSI Styling ---
GREEN = '\033[92m'
RED = '\033[91m'
AMBER = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
NC = '\033[0m' # No Color

# --- Secrets Management ---
AGENT_SECRETS = {
    "support-refund-agent": b'SUPPORT_AGENT_KMS_KEY_MATERIAL_SIM_04'
}

def sign_transaction_payload(agent_id: str, payload: dict) -> str:
    """Signs a JSON-serializable payload using the agent's symmetric key."""
    key = AGENT_SECRETS.get(agent_id)
    if not key: 
        raise ValueError(f"No secret key for agent '{agent_id}'")
    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    h = HMAC(key, hashes.SHA256())
    h.update(payload_bytes)
    return h.finalize().hex()

# --- BigQuery Configuration ---
PROJECT_ID = "zerotrust-svcsproject00-mngmnt"
DATASET_ID = "agent_orders"
PIPELINE_TABLE_ID = f"{PROJECT_ID}.{DATASET_ID}.transaction_pipeline"
LEDGER_TABLE_ID = f"{PROJECT_ID}.{DATASET_ID}.secure_ledger"

def process_pipeline():
    """
    Reads from the pipeline table, cryptographically verifies the signatures,
    and commits valid records to the secure ledger.
    """
    bq_client = bigquery.Client()

    try:
        print(f"\n{CYAN}[Process Job]{NC} Polling pipeline `{PIPELINE_TABLE_ID}`...")
        query_job = bq_client.query(f"SELECT * FROM `{PIPELINE_TABLE_ID}`")
        pending_transactions = [dict(row) for row in query_job]
    except Exception as e:
        print(f"{RED}✗ BigQuery Error:{NC} Failed to read pipeline: {e}")
        return

    if not pending_transactions:
        print(f"{GREEN}✓ No pending transactions in the pipeline.{NC}")
        return

    print(f"\n{BOLD}========================= PROCESSING ACTIVE PIPELINE ========================={NC}")
    
    for idx, tx in enumerate(pending_transactions, start=1):
        signature = tx['signature']
        payload_str = tx['payload']
        payload = json.loads(payload_str)
        agent_id = payload.get('agent_id', 'unknown')
        details = payload.get('details', {})
        order_id = details.get('order_id', 'N/A')
        amount = details.get('amount', 0.0)

        # Re-calculate the expected signature
        try:
            expected_sig = sign_transaction_payload(agent_id, payload)
        except ValueError:
            expected_sig = None

        print(f"\n{BOLD}Checking Transaction #{idx}:{NC}")
        print(f"  • Signature : {signature[:16]}... ")
        print(f"  • Action    : refunding ${amount:.2f} on Order #{order_id}")

        # Verification check
        if expected_sig and hmac_compare.compare_digest(expected_sig, signature):
            print(f"  • Status    : {GREEN}✓ PASSED{NC} (Cryptographic verification successful)")
            
            # Write to secure ledger
            try:
                row_to_insert = {
                    "signature": signature, "agent_id": agent_id, "action": payload.get('action'),
                    "order_id": order_id, "amount": amount, "item": details.get('item'),
                    "recipient": details.get('recipient'), "timestamp": payload.get('timestamp')
                }
                errors = bq_client.insert_rows_json(LEDGER_TABLE_ID, [row_to_insert])
                if not errors:
                    print(f"  • Action    : {GREEN}Committed{NC} to `{LEDGER_TABLE_ID}`")
                    # Remove from pipeline
                    cleanup_pipeline_row(bq_client, signature)
                else:
                    print(f"  • Action    : {RED}FAILED{NC} to write to ledger: {errors}")
            except Exception as e:
                print(f"  • Action    : {RED}FAILED{NC} with exception: {e}")
        else:
            print(f"  • Status    : {RED}✗ FAILED{NC} (Signature is corrupt, missing, or mismatched!)")
            print(f"  • Action    : {RED}REJECTED{NC} (Transaction dropped from the pipeline)")
            cleanup_pipeline_row(bq_client, signature)

    print(f"{BOLD}=============================================================================={NC}\n")


def audit_ledger() -> bool:
    """
    Performs an integrity audit. It recalculates the signature of every row 
    in the ledger to detect bypass attacks or database tampering.

    Returns True if every row verifies (or the ledger is empty), False if any
    row fails or the ledger can't be read (fail closed).
    """
    bq_client = bigquery.Client()
    try:
        print(f"\n{CYAN}[Audit Job]{NC} Fetching entire ledger from `{LEDGER_TABLE_ID}`...")
        query_job = bq_client.query(f"SELECT * FROM `{LEDGER_TABLE_ID}`")
        ledger_rows = [dict(row) for row in query_job]
    except Exception as e:
        print(f"{RED}✗ BigQuery Error:{NC} Failed to fetch ledger: {e}")
        return False

    if not ledger_rows:
        print(f"{AMBER}⚠️  Audit Complete: The secure ledger is empty.{NC}")
        return True

    print(f"\n{BOLD}=================== CRYPTOGRAPHIC SECURE LEDGER AUDIT ======================={NC}")
    audit_failed = False

    for idx, row in enumerate(ledger_rows, start=1):
        signature = row['signature']
        agent_id = row['agent_id']
        order_id = row['order_id']
        amount = row['amount']

        # Reconstruct the payload to re-sign and verify
        reconstructed_payload = {
            "agent_id": agent_id,
            "action": row['action'],
            "details": {
                "order_id": order_id,
                "amount": amount,
                "item": row['item'],
                "recipient": row['recipient']
            },
            "timestamp": _normalize_timestamp(row['timestamp'])
        }

        try:
            expected_sig = sign_transaction_payload(agent_id, reconstructed_payload)
        except ValueError:
            expected_sig = None

        print(f"\n{BOLD}Auditing Ledger Row #{idx}:{NC}")
        print(f"  • Transaction ID : Order #{order_id} (${amount:.2f})")
        print(f"  • Signature      : {signature[:16]}... ")

        # Perform the cryptographic comparison
        if expected_sig and hmac_compare.compare_digest(expected_sig, signature):
            print(f"  • Audit Status   : {GREEN}✓ SECURE{NC} (Row integrity is verified and intact)")
        else:
            print(f"  • Audit Status   : {RED}🚨 TAMPERED / INCORRECT SIGNATURE!{NC}")
            print(f"    Expected: {expected_sig if expected_sig else 'None'}")
            print(f"    Received: {signature}")
            audit_failed = True

    print(f"\n{BOLD}=============================================================================={NC}")
    if audit_failed:
        print(f"{RED}❌ AUDIT WARNING: Cryptographic tampering detected in the ledger!{NC}\n")
    else:
        print(f"{GREEN}✓ AUDIT SUCCESS: Ledger integrity is completely verified. All rows intact.{NC}\n")
    return not audit_failed


def _normalize_timestamp(value) -> str:
    """
    Returns the timestamp in the exact format it was signed with
    (time.strftime('%Y-%m-%dT%H:%M:%SZ')), whether the ledger column is a
    BigQuery TIMESTAMP (returned as a datetime) or a STRING.
    """
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc)
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    text = str(value).strip().replace(" ", "T")
    if text.endswith("Z"):
        text = text[:-1]
    text = text.split("+")[0].split(".")[0]  # drop UTC offset and fractional seconds
    return text + "Z"


def cleanup_pipeline_row(bq_client, signature):
    """Deletes processed rows from the transaction pipeline."""
    try:
        delete_query = f"DELETE FROM `{PIPELINE_TABLE_ID}` WHERE signature = @signature"
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("signature", "STRING", signature)]
        )
        bq_client.query(delete_query, job_config=job_config).result()
    except Exception as e:
         print(f"    {AMBER}↳ Cleanup notice: Row currently locked in buffer: {e}{NC}")


if __name__ == "__main__":
    # Check command-line arguments to determine execution mode.
    # NOTE: sys.argv is a list - compare the first argument, not the list itself.
    if len(sys.argv) > 1 and sys.argv[1].strip().lower() == "audit":
        # Non-zero exit on tampering so the audit can gate a CI job or alert.
        sys.exit(0 if audit_ledger() else 2)
    else:
        # Default behavior is processing the active pipeline
        process_pipeline()

# =================================================================
#              END OF THE COMPLETE db_guard.py FILE
# =================================================================