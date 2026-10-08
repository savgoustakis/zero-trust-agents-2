# =================================================================
#            START OF THE COMPLETE db_guard.py FILE
# =================================================================
#
# Database Guard: the only path from the transaction pipeline into the
# secure ledger.
#
# Write signing is ASYMMETRIC (Cloud KMS, RSA-PSS 2048 / SHA-256):
#   * agent.py signs each refund with its own KMS key (roles/cloudkms.signer).
#   * This guard holds NO secret. It only fetches the agent's PUBLIC key
#     (roles/cloudkms.publicKeyViewer) and verifies. Nothing in this file or
#     this repo can mint a valid signature, so a leaked repo or a compromised
#     guard can't forge refunds.
#   * Every failure path fails closed: unknown agent, malformed signature,
#     KMS unreachable, mismatch -> nothing is committed.

import base64
import binascii
import json
import sys
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from google.cloud import bigquery
from google.cloud import kms

# --- Terminal ANSI Styling ---
GREEN = '\033[92m'
RED = '\033[91m'
AMBER = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
NC = '\033[0m' # No Color

# --- BigQuery Configuration ---
PROJECT_ID = "zerotrust-svcsproject00-mngmnt"
DATASET_ID = "agent_orders"
PIPELINE_TABLE_ID = f"{PROJECT_ID}.{DATASET_ID}.transaction_pipeline"
LEDGER_TABLE_ID = f"{PROJECT_ID}.{DATASET_ID}.secure_ledger"

# --- Agent write-signing registry (public keys only) ---
# One KMS key per agent. The agent_id inside a payload only SELECTS a key from
# this allow-list; an agent that isn't registered here is rejected outright.
# Pinned to a key VERSION: after rotating, add the new version here (and keep
# the old one while its ledger rows still need to be audited).
WRITE_KEY_VERSIONS = {
    "support-refund-agent": (
        f"projects/{PROJECT_ID}/locations/global/keyRings/zerotrust-agent-keyring/"
        "cryptoKeys/zerotrust-agent-refund-key01/cryptoKeyVersions/1"
    ),
}
EXPECTED_WRITE_ALGORITHM = "RSA_SIGN_PSS_2048_SHA256"

_KMS_CLIENT = None
_PUBLIC_KEYS = {}  # agent_id -> cached public key


class VerifierUnavailable(Exception):
    """KMS couldn't give us the public key: we can't verify, so we must not commit."""


def _get_agent_public_key(agent_id: str):
    """Fetches (once) and caches the agent's write-signing public key from Cloud KMS."""
    global _KMS_CLIENT
    if agent_id not in _PUBLIC_KEYS:
        key_path = WRITE_KEY_VERSIONS[agent_id]
        try:
            if _KMS_CLIENT is None:
                _KMS_CLIENT = kms.KeyManagementServiceClient()
            pub = _KMS_CLIENT.get_public_key(name=key_path)
            # Pin the algorithm so a key-version swap can't silently change the scheme.
            if pub.algorithm.name != EXPECTED_WRITE_ALGORITHM:
                raise ValueError(f"unexpected algorithm {pub.algorithm.name}, expected {EXPECTED_WRITE_ALGORITHM}")
            _PUBLIC_KEYS[agent_id] = load_pem_public_key(pub.pem.encode("utf-8"))
        except Exception as e:
            raise VerifierUnavailable(str(e)) from e
    return _PUBLIC_KEYS[agent_id]


def verify_write_signature(agent_id: str, payload: dict, signature_b64) -> tuple:
    """
    Verifies a refund payload against the agent's KMS public key.

    Returns (ok, reason). Raises VerifierUnavailable if the public key can't be
    fetched - callers must treat that as "not verified" (fail closed).
    """
    if agent_id not in WRITE_KEY_VERSIONS:
        return False, f"no registered signing key for agent '{agent_id}'"
    if not signature_b64:
        return False, "missing signature"
    try:
        sig_bytes = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return False, "malformed signature (not a KMS RSA signature)"

    public_key = _get_agent_public_key(agent_id)
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    try:
        public_key.verify(
            sig_bytes,
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),  # as used by Cloud KMS
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False, "signature does not match payload (edited after signing, or signed by another key)"
    return True, "verified against KMS public key (RSA-PSS 2048)"


def _already_in_ledger(bq_client, signature: str) -> bool:
    """True if this exact signed write was already committed (replayed/duplicate row). Raises on error."""
    query = f"SELECT COUNT(*) AS n FROM `{LEDGER_TABLE_ID}` WHERE signature = @signature"
    job_config = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("signature", "STRING", signature)]
    )
    rows = list(bq_client.query(query, job_config=job_config))
    return bool(rows) and rows[0]['n'] > 0


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
        signature = tx.get('signature')
        payload_str = tx.get('payload')
        print(f"\n{BOLD}Checking Transaction #{idx}:{NC}")
        print(f"  • Signature : {str(signature)[:16]}... ")

        try:
            payload = json.loads(payload_str)
            agent_id = payload.get('agent_id', 'unknown')
            details = payload.get('details', {})
            order_id = details.get('order_id', 'N/A')
            amount = float(details.get('amount', 0.0))
        except Exception:
            print(f"  • Status    : {RED}✗ FAILED{NC} (Payload is not valid JSON)")
            print(f"  • Action    : {RED}REJECTED{NC} (Transaction dropped from the pipeline)")
            cleanup_pipeline_row(bq_client, signature, payload_str)
            continue

        print(f"  • Action    : refunding ${amount:.2f} on Order #{order_id} (agent: {agent_id})")

        # 1. Verify the signature with the agent's PUBLIC key
        try:
            ok, reason = verify_write_signature(agent_id, payload, signature)
        except VerifierUnavailable as e:
            # Can't verify -> don't commit. Don't delete either: the row may be
            # legitimate, so leave it for the next run once KMS is reachable.
            print(f"  • Status    : {AMBER}⚠ UNVERIFIABLE{NC} (KMS public key unavailable: {e})")
            print(f"  • Action    : {AMBER}HELD{NC} (Failing closed - left in the pipeline, not committed)")
            continue

        if not ok:
            print(f"  • Status    : {RED}✗ FAILED{NC} ({reason})")
            print(f"  • Action    : {RED}REJECTED{NC} (Transaction dropped from the pipeline)")
            cleanup_pipeline_row(bq_client, signature, payload_str)
            continue

        print(f"  • Status    : {GREEN}✓ PASSED{NC} ({reason})")

        # 2. A valid signature proves WHO signed, not that it's the first time we've
        #    seen it: refuse to commit the same signed write twice.
        try:
            if _already_in_ledger(bq_client, signature):
                print(f"  • Action    : {RED}REJECTED{NC} (Already in the ledger - duplicate/replayed write dropped)")
                cleanup_pipeline_row(bq_client, signature, payload_str)
                continue
        except Exception as e:
            print(f"  • Action    : {AMBER}HELD{NC} (Couldn't check the ledger for duplicates: {e})")
            continue

        # 3. Write to secure ledger
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
                cleanup_pipeline_row(bq_client, signature, payload_str)
            else:
                print(f"  • Action    : {RED}FAILED{NC} to write to ledger: {errors}")
        except Exception as e:
            print(f"  • Action    : {RED}FAILED{NC} with exception: {e}")

    print(f"{BOLD}=============================================================================={NC}\n")


def audit_ledger() -> bool:
    """
    Performs an integrity audit. It re-verifies the KMS signature of every row
    in the ledger to detect bypass attacks or database tampering.

    Returns True if every row verifies (or the ledger is empty), False if any
    row fails, can't be verified, or the ledger can't be read (fail closed).
    Note: this detects EDITED rows and rows inserted without a valid signature.
    It can't see rows that were DELETED.
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

        # Reconstruct the payload exactly as the agent signed it
        reconstructed_payload = {
            "agent_id": agent_id,
            "action": row['action'],
            "details": {
                "order_id": order_id,
                "amount": float(amount) if amount is not None else None,  # agent signs amount as a float
                "item": row['item'],
                "recipient": row['recipient']
            },
            "timestamp": _normalize_timestamp(row['timestamp'])
        }

        print(f"\n{BOLD}Auditing Ledger Row #{idx}:{NC}")
        print(f"  • Transaction ID : Order #{order_id} (${float(amount or 0):.2f})")
        print(f"  • Signature      : {str(signature)[:16]}... ")

        try:
            ok, reason = verify_write_signature(agent_id, reconstructed_payload, signature)
        except VerifierUnavailable as e:
            ok, reason = False, f"cannot verify - KMS public key unavailable ({e})"

        if ok:
            print(f"  • Audit Status   : {GREEN}✓ SECURE{NC} (Row integrity is verified and intact)")
        else:
            print(f"  • Audit Status   : {RED}🚨 TAMPERED / INCORRECT SIGNATURE!{NC}")
            print(f"    Reason: {reason}")
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


def cleanup_pipeline_row(bq_client, signature, payload_str):
    """
    Deletes a processed row from the transaction pipeline.
    Matches on signature AND payload, so rejecting a forgery that reuses a real
    signature never deletes the genuine row it was copied from.
    """
    try:
        delete_query = (
            f"DELETE FROM `{PIPELINE_TABLE_ID}` "
            "WHERE signature IS NOT DISTINCT FROM @signature AND payload IS NOT DISTINCT FROM @payload"
        )
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("signature", "STRING", signature),
                bigquery.ScalarQueryParameter("payload", "STRING", payload_str),
            ]
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