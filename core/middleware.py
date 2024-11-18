import re
from numpy._core.defchararray import startswith
import pandas as pd
import joblib  # or any other model loading mechanism
import logging
import httpx
from django.http import JsonResponse, HttpResponse,HttpResponseRedirect
from fa_imp.sus import bad_words  # Ensure `bad_words` is correctly imported
from django.conf import settings
import os
import requests
from urllib.parse import urljoin
# Destination URL (web application)
DESTINATION_URL = "http://localhost:8000"  # Modify to your web application's URL
ROUTE_IDENTIFIERS = ['/iot', '/app2', '/app3']
ROUTE_DESTINATIONS = {
    '/iot': 'http://localhost:8000',
    '/app2': 'http://app2.internal.local',
    '/app3': 'http://app3.internal.local',
}

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
        # Load the ML model
        self.model = joblib.load(os.path.join(settings.BASE_DIR, "fa_imp", "request_threat_model.pkl"))
        
    def __call__(self, request):
        # Get client IP
        origin_ip = self.get_client_ip(request)
        logging.info(f"Request received from IP: {origin_ip} to PATH: {request.path}")

        # First analyze the request for threats
        if not self.analyze_request(request):
            logging.warning(f"Blocked request from IP: {origin_ip} to PATH: {request.path}")
            return JsonResponse({"error": "Request blocked due to security threat"}, status=403)

        # If request is safe, handle proxying
        response = self.handle_proxy(request)
        return response

    def handle_proxy(self, request):
        """Handle the proxying of requests"""
        for route in ROUTE_IDENTIFIERS:
            if request.path.startswith(route):
                return self.proxy_request(request, route)
        
        # No proxy route matched, continue with normal processing
        return self.get_response(request)

    def proxy_request(self, request, route):
        """Proxy the request to the appropriate destination"""
        try:
            destination_url = ROUTE_DESTINATIONS.get(route)
            if not destination_url:
                return self.get_response(request)

            # Construct the forward URL
            forward_path = request.path[len(route):]
            forward_url = urljoin(destination_url, forward_path)
            
            # Prepare headers
            headers = self.prepare_headers(request)
            
            # Handle streaming uploads
            data = request.body if request.method in ['POST', 'PUT', 'PATCH'] else None
            
            # Make the proxied request
            response = requests.request(
                method=request.method,
                url=forward_url,
                headers=headers,
                data=data,
                params=request.GET,
                cookies=request.COOKIES,
                stream=True,
                verify=True
            )

            # Create Django response
            django_response = HttpResponse(
                content=response.content,
                status=response.status_code,
                content_type=response.headers.get('Content-Type', '')
            )

            # Forward response headers
            self.forward_response_headers(response, django_response)

            return django_response

        except requests.RequestException as e:
            logging.error(f"Proxy error: {str(e)}")
            return JsonResponse({"error": "Proxy Error", "details": str(e)}, status=502)
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}")
            return JsonResponse({"error": "Internal Server Error"}, status=500)

    def prepare_headers(self, request):
        """Prepare headers for the proxied request"""
        headers = {}
        for key, value in request.META.items():
            # Common headers to forward
            if key.startswith('HTTP_'):
                header_key = key[5:].replace('_', '-').title()
                # Skip hop-by-hop headers
                if header_key.lower() not in [
                    'connection', 'keep-alive', 'proxy-authenticate', 
                    'proxy-authorization', 'te', 'trailers', 
                    'transfer-encoding', 'upgrade'
                ]:
                    headers[header_key] = value
            elif key in ['CONTENT_TYPE', 'CONTENT_LENGTH']:
                headers[key.replace('_', '-').title()] = value

        # Add X-Forwarded headers
        headers['X-Forwarded-For'] = self.get_client_ip(request)
        headers['X-Forwarded-Proto'] = request.scheme
        headers['X-Forwarded-Host'] = request.get_host()

        return headers

    def forward_response_headers(self, response, django_response):
        """Forward headers from the proxied response to Django response"""
        excluded_headers = {
            'content-encoding', 'transfer-encoding', 'connection',
            'keep-alive', 'proxy-authenticate', 'proxy-authorization',
            'te', 'trailers', 'upgrade'
        }

        for header, value in response.headers.items():
            if header.lower() not in excluded_headers:
                django_response[header] = value

    # Your existing methods remain unchanged
    def get_client_ip(self, request):
        """Extract the client IP address from the request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


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
    



    def forward_request3(self, request):
        # Forward the request to the destination application
        for route in ROUTE_IDENTIFIERS:
            if request.path.startswith(route):
                # If the path matches one of the identifiers, forward to the appropriate route
                destination_url = ROUTE_DESTINATIONS.get(route, None)
                if destination_url:
                    try:
                        # Construct the full URL
                        forward_url = urljoin(destination_url, request.path[len(route):])
                        logging.info(f"Forwarding request from {request.path} to {forward_url}")

                        # Forward the request with the same method and headers
                        # Extract headers from the original request
                        headers = {
                            key: value 
                            for key, value in request.META.items() 
                            if key.startswith('HTTP_')
                        }
                        # Clean up header names
                        headers = {
                            key[5:].replace('_', '-').title(): value 
                            for key, value in headers.items()
                        }

                        # Forward the request
                        response = requests.request(
                            method=request.method,
                            url=forward_url,
                            headers=headers,
                            data=request.body if request.method in ['POST', 'PUT', 'PATCH'] else None,
                            params=request.GET,
                            stream=True,
                            verify=True  # SSL verification
                        )

                        # Create Django response from the requests response
                        django_response = HttpResponse(
                            content=response.content,
                            status=response.status_code,
                            content_type=response.headers.get('Content-Type', '')
                        )

                        # Forward relevant headers from the response
                        for header, value in response.headers.items():
                            if header.lower() not in ['content-encoding', 'transfer-encoding']:
                                django_response[header] = value

                        return django_response

                    except requests.RequestException as e:
                        logging.error(f"Error forwarding request: {e}")
                        return JsonResponse(
                            {"error": "Error forwarding request", "details": str(e)}, 
                            status=502
                        )

        # If no route matches, continue with normal Django processing (current app)
        try:
            # Continue with normal Django request handling
            response = self.get_response(request)
            return response
        except Exception as e:
            logging.error(f"Error processing request: {e}")
            return JsonResponse({"error": "Internal Server Error"}, status=500)



    def forward_request2(self, request):
        # Forward the request to the destination application
        for route in ROUTE_IDENTIFIERS:
            if request.path.startswith(route):
                # If the path matches one of the identifiers, redirect to the appropriate route
                redirect_url = ROUTE_DESTINATIONS.get(route, None)
                if redirect_url:
                    logging.info(f"Redirecting request from {request.path} to {redirect_url}")
                    return HttpResponseRedirect(redirect_url + request.path[len(route):])

        # If no route matches, continue with normal Django processing (current app)
        try:
            # Continue with normal Django request handling
            response = self.get_response(request)
            return response
        except Exception as e:
            logging.error(f"Error processing request: {e}")
            return JsonResponse({"error": "Internal Server Error"}, status=500)
        
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
