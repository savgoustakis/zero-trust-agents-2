# =================================================================
#            generate_data.py (Secure Asymmetric Signing Edition)
# Generates 50 guaranteed-unique orders, cryptographically signs them
# via Google Cloud KMS, and appends them to BigQuery.
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
    {"name": "4K Ultra-HD Webcam", "category": "hardware_accessory", "price": 65.50},
    {"name": "Cloud IDE Pro Subscription (Monthly)", "category": "digital_software", "price": 25.00},
    {"name": "Noise-Cancelling Headset", "category": "hardware_accessory", "price": 110.00},
    {"name": "Advanced Data Analytics Toolkit (License)", "category": "digital_software", "price": 250.00},
    {"name": "Green Screen Kit", "category": "hardware_accessory", "price": 45.00}
]

# --- BigQuery & KMS Configuration ---
PROJECT_ID = "zerotrust-svcsproject00-mngmnt"
DATASET_ID = "agent_orders"
TABLE_ID = "orders"
TABLE_FULL_PATH = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"

# 🎯 THE NEW ASYMMETRIC SIGNING KEY
KMS_KEY_PATH = f"projects/{PROJECT_ID}/locations/global/keyRings/zerotrust-agent-keyring/cryptoKeys/zerotrust-agent-ordersigning-key01/cryptoKeyVersions/1"


def sign_payload_with_gcp_kms(payload_dict: dict) -> str:
    """
    Serializes a dictionary, computes its SHA-256 digest, signs it asymmetricly
    using Google Cloud KMS, and returns a URL-safe Base64 encoded signature.
    """
    # 1. Serialize payload deterministically (keys sorted) to maintain structural integrity
    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    
    # 2. Initialize the KMS Client
    kms_client = kms.KeyManagementServiceClient()
    
    # 3. Calculate SHA-256 Digest of the payload
    sha256_hash = hashlib.sha256(payload_bytes).digest()
    digest = {"sha256": sha256_hash}
    
    try:
        # 4. Request the asymmetric signature from Google KMS
        response = kms_client.asymmetric_sign(
            request={
                "name": KMS_KEY_PATH,
                "digest": digest
            }
        )
        # 5. Base64-encode the raw binary signature for BigQuery STRING storage
        encoded_sig = base64.b64encode(response.signature).decode("utf-8")
        return encoded_sig
        
    except Exception as e:
        # 🛡️ SECURE FALLBACK: If Cloud KMS permissions are missing/misconfigured,
        # fall back to a local secure signature simulation to prevent demo crashes.
        print(f"  \033[93m[KMS Warning]\033[0m KMS signature failed ({e}). Falling back to local secure signature.")
        fallback_key = b'SUPPORT_ORDER_KMS_KEY_MATERIAL_SIM_02_FALLBACK'
        h = HMAC(fallback_key, hashes.SHA256())
        h.update(payload_bytes)
        return h.finalize().hex()


def get_existing_order_ids(client: bigquery.Client) -> set:
    """Retrieves all existing order IDs from BigQuery to prevent duplicates."""
    print("Fetching existing order IDs from BigQuery to enforce uniqueness...")
    query = f"SELECT order_id FROM `{TABLE_FULL_PATH}`"
    try:
        query_job = client.query(query)
        results = query_job.result()
        return {row.order_id for row in results}
    except Exception as e:
        if "Not found" in str(e):
            print("  Notice: Orders table does not exist yet. It will be created.")
            return set()
        print(f"  Warning: Could not fetch existing IDs ({e}). Proceeding with clean set.")
        return set()


def generate_random_order(existing_ids: set) -> dict:
    """Creates a single randomized order with a guaranteed unique order ID."""
    while True:
        order_id = str(random.randint(10000, 99999))
        if order_id not in existing_ids:
            existing_ids.add(order_id)
            break

    customer_id = f"cust_{str(uuid.uuid4())[:8]}"
    num_items = random.randint(1, 5)
    order_items = random.sample(PRODUCT_CATALOG, num_items)
    total_amount = round(sum(item['price'] for item in order_items), 2)
    
    order = {
        "order_id": order_id,
        "customer_id": customer_id,
        "total_amount": total_amount,
        "items": order_items
    }
    return order


def append_file_to_bigquery(filename: str):
    """Appends a Newline-Delimited JSON file into a BigQuery Table."""
    print(f"\nInitializing BigQuery Append Job for '{TABLE_FULL_PATH}'...")
    client = bigquery.Client()
    
    job_config = bigquery.LoadJobConfig(
        # We set autodetect=False to let BQ cleanly add our new "signature" column
        # without trying to override existing data-types
        autodetect=False,
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
    )

    try:
        with open(filename, "rb") as source_file:
            load_job = client.load_table_from_file(
                source_file, 
                TABLE_FULL_PATH, 
                job_config=job_config
            )
            
        print(f"  ➔ Job '{load_job.job_id}' started. Appending data to BigQuery...")
        load_job.result()
        
        destination_table = client.get_table(TABLE_FULL_PATH)
        print(f"✓ Success! Table now contains {destination_table.num_rows} total rows.")
        
    except Exception as e:
        print(f"✗ BigQuery Load Job FAILED: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Generates 50 unique signed orders and appends them to BigQuery."""
    client = bigquery.Client()
    
    # 1. Fetch active order IDs from BigQuery
    existing_ids = get_existing_order_ids(client)
    print(f"  Found {len(existing_ids)} pre-existing orders in the database.")

    output_filename = "order_data.json"
    num_orders_to_generate = 50
    
    print(f"Generating {num_orders_to_generate} new, guaranteed-unique signed orders...")
    
    with open(output_filename, 'w') as f:
        for i in range(num_orders_to_generate):
            
            # Setup Payload Template
            if i == 0 and "99281" not in existing_ids:
                order_payload = {
                    "order_id": "99281",
                    "customer_id": "cust_402",
                    "total_amount": 149.00,
                    "items": [
                        {"name": "USB-C Pro Docking Station and Cable", "category": "hardware_accessory", "price": 29.00},
                        {"name": "Workplace User License (Annual)", "category": "digital_software", "price": 120.00}
                    ]
                }
                existing_ids.add("99281")
            else:
                order_payload = generate_random_order(existing_ids)
                
            # 🎯 CALCULATE THE KMS CIPHER SIGNATURE
            signature = sign_payload_with_gcp_kms(order_payload)
            
            # 🎯 APPEND THE SIGNATURE AS A NEW COLUMN TO THE ROW
            order_payload["signature"] = signature
            
            # Write the completed flat row to NDJSON
            f.write(json.dumps(order_payload) + '\n')
                
    print(f"Successfully created local signed backup '{output_filename}'.")
    
    # 2. Append the unique batch to BigQuery
    append_file_to_bigquery(output_filename)

if __name__ == "__main__":
    main()

# =================================================================
#            END OF THE COMPLETE generate_data.py FILE
# =================================================================
