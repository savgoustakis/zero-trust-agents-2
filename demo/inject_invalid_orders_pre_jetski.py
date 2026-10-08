# =================================================================
#            inject_invalid_orders.py
# Injects 10 cryptographically invalid orders into the BigQuery
# 'orders' table to test Agent verification defenses.
# =================================================================

import json
import random
import uuid
import sys
import hashlib
import base64
from google.cloud import bigquery
from google.cloud import kms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

# --- Predefined Product Catalog ---
PRODUCT_CATALOG = [
    {"name": "USB-C Pro Docking Station and Cable", "category": "hardware_accessory", "price": 29.00},
    {"name": "Workplace User License (Annual)", "category": "digital_software", "price": 120.00},
    {"name": "Ergonomic Mechanical Keyboard", "category": "hardware_accessory", "price": 89.99},
    {"name": "4K Ultra-HD Webcam", "category": "hardware_accessory", "price": 65.50}
]

# --- BigQuery & KMS Configuration ---
PROJECT_ID = "zerotrust-svcsproject00-mngmnt"
DATASET_ID = "agent_orders"
TABLE_ID = "orders"
TABLE_FULL_PATH = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"
KMS_KEY_PATH = f"projects/{PROJECT_ID}/locations/global/keyRings/zerotrust-agent-keyring/cryptoKeys/zerotrust-agent-key03/cryptoKeyVersions/1"
ROGUE_SECRET_KEY = b'ATTACKER_MALICIOUS_KEY_MATERIAL_666'

def sign_payload_with_gcp_kms(payload_dict: dict) -> str:
    """Signs using the legitimate KMS key or local fallback."""
    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    try:
        kms_client = kms.KeyManagementServiceClient()
        sha256_hash = hashlib.sha256(payload_bytes).digest()
        response = kms_client.asymmetric_sign(
            request={"name": KMS_KEY_PATH, "digest": {"sha256": sha256_hash}}
        )
        return base64.b64encode(response.signature).decode("utf-8")
    except Exception as e:
        fallback_key = b'SUPPORT_ORDER_KMS_KEY_MATERIAL_SIM_02_FALLBACK'
        h = HMAC(fallback_key, hashes.SHA256())
        h.update(payload_bytes)
        return h.finalize().hex()

def append_file_to_bigquery(filename: str):
    """Appends the malformed NDJSON file to the BigQuery orders table."""
    print(f"\nInitializing BigQuery Append Job for '{TABLE_FULL_PATH}'...")
    client = bigquery.Client()
    job_config = bigquery.LoadJobConfig(
        autodetect=False, # Must be False to preserve existing schema
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
    )
    try:
        with open(filename, "rb") as source_file:
            load_job = client.load_table_from_file(source_file, TABLE_FULL_PATH, job_config=job_config)
        load_job.result()
        destination_table = client.get_table(TABLE_FULL_PATH)
        print(f"✓ Success! Table now contains {destination_table.num_rows} total rows.")
    except Exception as e:
        print(f"✗ BigQuery Load Job FAILED: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    print("\nStarting Exploit Injection Suite for the 'orders' table...")
    output_filename = "invalid_orders_data.json"
    
    with open(output_filename, 'w') as f:
        for i in range(10):
            # 1. Generate base legitimate order structure
            order_id = str(random.randint(10000, 99999))
            order_items = random.sample(PRODUCT_CATALOG, random.randint(1, 3))
            total_amount = round(sum(item['price'] for item in order_items), 2)
            
            order_payload = {
                "order_id": order_id,
                "customer_id": f"cust_{str(uuid.uuid4())[:8]}",
                "total_amount": total_amount,
                "items": order_items
            }

            # 2. Apply Attack Vectors
            if i < 3:
                # EXPLOIT 1: No Signature / Garbage Signature (Rows 1-3)
                order_payload["signature"] = "NULL_OR_GARBAGE_SIGNATURE_STRING"
                print(f"  ➔ [INJECTED] Exploit 1 (Garbage Signature) on Order #{order_id}")
                
            elif i < 6:
                # EXPLOIT 2: Signed with Unauthorized Rogue Key (Rows 4-6)
                payload_bytes = json.dumps(order_payload, sort_keys=True).encode('utf-8')
                h_rogue = HMAC(ROGUE_SECRET_KEY, hashes.SHA256())
                h_rogue.update(payload_bytes)
                order_payload["signature"] = f"ROGUE_{h_rogue.finalize().hex()}"
                print(f"  ➔ [INJECTED] Exploit 2 (Rogue Key) on Order #{order_id}")
                
            else:
                # EXPLOIT 3: Payload Tampering (Rows 7-10)
                # Sign the legitimate payload first
                legit_signature = sign_payload_with_gcp_kms(order_payload)
                order_payload["signature"] = legit_signature
                # Tamper with the total_amount POST-signature
                order_payload["total_amount"] = 110 
                print(f"  ➔ [INJECTED] Exploit 3 (Tampered Amount -> $110) on Order #{order_id}")

            # 3. Write to local file
            f.write(json.dumps(order_payload) + '\n')
            
    print(f"\nSuccessfully created local exploit file '{output_filename}'.")
    
    # 4. Upload to BigQuery
    append_file_to_bigquery(output_filename)
    print("\nInjection complete! Test these Order IDs in your Agent to verify it detects the corruption.")

if __name__ == "__main__":
    main()
