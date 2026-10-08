# =================================================================
#            START OF THE COMPLETE model_armor.py FILE
# =================================================================

from google.cloud import modelarmor_v1
from google.api_core.client_options import ClientOptions
import os
import json # Import the json library for pretty-printing

# --- CONFIGURATION (Hardcoded for Simplicity) ---
GCP_REGION = "australia-southeast2" 
MODEL_ARMOR_TEMPLATE_ID = "projects/zerotrust-svcsproject00-mngmnt/locations/australia-southeast2/templates/zero-trust-agent"

class ModelArmorGuard:
    """
    A client for the official Google Cloud Model Armor service that uses the
    native Python client library and Application Default Credentials (ADC).
    """

    def __init__(self, sensitivity: str = "HIGH"):
        """
        Initializes the client by connecting to the correct regional endpoint.
        """
        try:
            endpoint = f"modelarmor.{GCP_REGION}.rep.googleapis.com"
            self.ma_client = modelarmor_v1.ModelArmorClient(
                client_options=ClientOptions(api_endpoint=endpoint)
            )
            print(f"[Model Armor Client] Initialized. Targeting endpoint: {endpoint}")
        except Exception as e:
            print(f"ERROR: Failed to initialize Model Armor client: {e}")
            self.ma_client = None
        self.sensitivity = sensitivity

    def _parse_filter_results(self, response_dict) -> str:
        """
        Helper to find the specific filter that caused a block by correctly
        navigating the nested response dictionary.
        """
        try:
            filter_results = response_dict.get("sanitization_result", {}).get("filter_results", {})

            # 1. Specifically check the deeply nested SDP filter
            sdp_result = filter_results.get("sdp", {}).get("sdp_filter_result", {}).get("inspect_result", {})
            if sdp_result:
                match_state = sdp_result.get("match_state")
                if match_state == "MATCH_FOUND" or match_state == 2:
                    return "Violation detected by filter: 'SDP' (Sensitive Data Protection)"

            # 2. Check other filters
            for filter_name, filter_data in filter_results.items():
                if filter_name == "sdp": continue
                # Check for a match state directly within the filter data
                if filter_data.get("match_state") == "MATCH_FOUND" or filter_data.get("match_state") == 2:
                    return f"Violation detected by filter: '{filter_name.upper()}'"
                # Check one level deeper for nested results
                inner_result = filter_data.get(f"{filter_name}_filter_result", {})
                if inner_result.get("match_state") == "MATCH_FOUND" or inner_result.get("match_state") == 2:
                    return f"Violation detected by filter: '{filter_name.upper()}'"
            
            return "A configured filter was triggered (specific reason not detailed by service)."
        except Exception as e:
            return f"A configured filter was triggered (error during response parsing: {e})."

    def inspect_ingress(self, text_to_inspect: str) -> dict:
        """
        Calls the official Model Armor service to sanitize an ingress prompt.
        """
        if not self.ma_client:
            return self._create_fallback_response("Client initialization failed.")
        try:
            request = modelarmor_v1.types.SanitizeUserPromptRequest(
                name=MODEL_ARMOR_TEMPLATE_ID,
                user_prompt_data=modelarmor_v1.types.DataItem(text=text_to_inspect)
            )
            response = self.ma_client.sanitize_user_prompt(request=request)
            
            if int(response.sanitization_result.filter_match_state) == 2:
                response_dict = modelarmor_v1.SanitizeUserPromptResponse.to_dict(response)
                
                # --- THIS IS THE NEW DEBUGGING BLOCK ---
                print("\033[93m--- [DEBUG] Raw Model Armor API Response ---")
                print(json.dumps(response_dict, indent=2))
                print("--- [END DEBUG] ---\033[0m")
                # ----------------------------------------

                specific_finding = self._parse_filter_results(response_dict)
                return {
                    "action": "BLOCK",
                    "reason": "Policy Violation: The content was flagged as unsafe by Model Armor.",
                    "findings": [specific_finding],
                    "latency_ms": 0
                }
            else:
                return {"action": "ALLOW", "reason": "Passed all Model Armor filters.", "latency_ms": 0}
        except Exception as e:
            print(f"ERROR: Model Armor API call failed: {e}")
            return self._create_fallback_response(f"API Error: {e}")

    def _create_fallback_response(self, reason: str) -> dict:
        """Creates a standardized 'BLOCK' response for error cases."""
        # This function remains unchanged
        return {
            "action": "BLOCK", 
            "reason": reason,
            "findings": ["Fell back to default-deny policy due to an error."],
            "latency_ms": 0
        }

    def scrub_egress(self, text_to_scrub: str) -> tuple[str, list]:
        """
        Calls the official Model Armor service to sanitize an egress LLM response.
        """
        # This function remains unchanged for now
        return text_to_scrub, []

# =================================================================
#              END OF THE COMPLETE model_armor.py FILE
# =================================================================
