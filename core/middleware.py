import re
from numpy._core.defchararray import startswith
import pandas as pd
import joblib  # or any other model loading mechanism
import logging
import httpx
from django.http import JsonResponse, HttpResponse
from fa_imp.sus import bad_words  # Ensure `bad_words` is correctly imported
from django.conf import settings
import os
# Destination URL (web application)
DESTINATION_URL = "http://localhost:8000"  # Modify to your web application's URL

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(settings.BASE_DIR,'logs', "app_logs.log")),  # Log to file 'app_logs.log'
        logging.StreamHandler()  # Also output logs to console
    ]
)

# Load the machine learning model (ensure this is the correct path to your model file)
model = joblib.load(os.path.join(settings.BASE_DIR,"fa_imp","request_threat_model.pkl"))  # Modify with the correct path to your saved model

class ThreatDetectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response


    def get_client_ip(self, request):
        """Extract the client IP address from the request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]  # Get the first IP in the list
        else:
            ip = request.META.get('REMOTE_ADDR')  # Fallback to REMOTE_ADDR
        return ip


    def __call__(self, request):
        # Analyze the request

        path = request.path
        query_params = request.GET.urlencode()  # Get query parameters as a string
        print(path)
        if not startswith(path,"/check"):
            return self.forward_request(request)
        origin_ip = self.get_client_ip(request)

        logging.info(f"Request received from IP: {origin_ip} to PATH: {request.path}")
        if not self.analyze_request(request):
            logging.warning(f"Blocked request from IP: {origin_ip} to PATH: {request.path}")
            return JsonResponse({"error": "Request blocked due to security threat"}, status=403)

        # Forward the request if safe
        return self.forward_request(request)

    def analyze_request(self, request):
        # Extract data from the request
        path = request.path
        query_params = request.GET.urlencode()  # Get query parameters as a string
        body = request.body.decode("utf-8") if request.method != "GET" else ""

        origin_ip = self.get_client_ip(request)
        path += query_params

        # Analyze the path and body for symbols and bad words
        path_features = self.analyze_string(path, "path")
        body_features = self.analyze_string(body, "body")

        # Combine the features
        combined_features = {**path_features, **body_features}

        # Prepare the feature dataframe for prediction
        feature_columns = [
            'path_single_q', 'path_double_q', 'path_dashes', 'path_braces', 'path_spaces',
            'path_percentages', 'path_semicolons', 'path_angle_brackets', 'path_special_chars',
            'path_badwords_count', 'body_single_q', 'body_double_q', 'body_dashes', 'body_braces',
            'body_spaces', 'body_percentages', 'body_semicolons', 'body_angle_brackets',
            'body_special_chars', 'body_badwords_count', 'path_length', 'body_length'
        ]

        # Create a DataFrame for the input features
        feature_data = pd.DataFrame([combined_features], columns=feature_columns)
        feature_data.fillna(0, inplace=True)

        # Check for bad words in path or body
        if any(word.lower() in path.lower() for word in bad_words) or \
           any(word.lower() in body.lower() for word in bad_words):
               logging.info("Bad word detected in path or body, Request from IP:{origin_ip} to PATH {path}")
               return False  # Block the request

        # Predict using the trained model
        prediction = model.predict(feature_data)

        # Block if model predicts a threat
        if prediction[0] == 1:
            logging.info(f"Threat detected based on model prediction: {combined_features}, Request from IP:{origin_ip} to PATH {path} ")
            return False

        return True  # Allow the request if no threats are detected

    def analyze_string(self, input_string, source):
        # Remove multipart boundaries
        if re.search(r'(--.*--)', input_string):
            input_string = re.sub(r'(--.*--)', '', input_string)

        # Initialize a dictionary to hold the symbol counts
        symbols = {
            'single_q': 0, 'double_q': 0, 'dashes': 0, 'braces': 0, 'spaces': 0,
            'percentages': 0, 'semicolons': 0, 'angle_brackets': 0, 'special_chars': 0
        }

        # Count occurrences of different symbols
        for char in input_string:
            if char == "'":
                symbols['single_q'] += 1
            elif char == '"':
                symbols['double_q'] += 1
            elif char == '-':
                symbols['dashes'] += 1
            elif char in '{}':
                symbols['braces'] += 1
            elif char == ' ':
                symbols['spaces'] += 1
            elif char == '%':
                symbols['percentages'] += 1
            elif char == ';':
                symbols['semicolons'] += 1
            elif char in '<>':
                symbols['angle_brackets'] += 1
            elif not char.isalnum() and not char.isspace():
                symbols['special_chars'] += 1

        # Count the length of the input string
        length_feature = len(input_string)

        # Count bad words
        badword_count = sum(1 for word in bad_words if word.lower() in input_string.lower())

        # Return the feature dict with 'source_' prefix (e.g., 'path_' or 'body_')
        features = {f'{source}_{key}': value for key, value in symbols.items()}
        features[f'{source}_length'] = length_feature
        features[f'{source}_badwords_count'] = badword_count

        return features

    def forward_request(self, request):
        # Forward the request to the destination application
        try:
            with httpx.Client(follow_redirects=False) as client:
                response = client.request(
                    method=request.method,
                    url=f"{DESTINATION_URL}{request.path}",
                    headers=dict(request.headers),
                    params=request.GET,
                    data=request.body
                )
                return HttpResponse(response.content, status=response.status_code, headers=response.headers)
        except Exception as e:
            logging.error(f"Error forwarding request: {e}")
            return JsonResponse({"error": "Internal Server Error"}, status=500)
