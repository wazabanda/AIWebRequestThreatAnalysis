import os
import django


# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'AIWebRequestThreatAnalysis.settings')

# Setup Django
django.setup()

import re
import pandas as pd
import joblib  # or any other model loading mechanism
from fastapi import FastAPI, Request, Response
import httpx
import logging
from fa_imp.sus import bad_words
from django.conf import settings
from core.models import *
from asgiref.sync import sync_to_async
import urllib.parse
from async_helpers.helpers import *
# Initialize FastAPI app
app = FastAPI()

# Destination URL (web application)
DESTINATION_URL = "http://localhost:8000"  # Modify to your web application's URL
DESTINATION_URL_BAD = "http://localhost:8001"  # Modify to your web application's URL

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

def get_client_ip(request: Request) -> str:
    # Try to get the IP from the 'X-Forwarded-For' header (in case of a proxy)
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        # The first IP in the list is usually the client's original IP
        return x_forwarded_for.split(",")[0]
    
    # If no 'X-Forwarded-For' header, fall back to the request's client
    return request.client.host

def parse_form_data(body: bytes | str) -> dict:
    """
    Parse URL-encoded form data into a clean dictionary.
    """
    if isinstance(body, bytes):
        body = body.decode('utf-8')
        
    form_dict = {}
    try:
        parsed = parse_qs(body)
        for key, values in parsed.items():
            value = values[0] if values else ''
            decoded_value = unquote_plus(value)
            form_dict[key] = decoded_value
            
        logging.info(f"Parsed form data: {form_dict}")
        return form_dict
    except Exception as e:
        logging.error(f"Error parsing form data: {e}")
        return {}


def check_for_bad_words(path, body, origin_ip, bad_words, logging_function=logging.info):
    """
    Check path and body for potentially malicious words
    
    :param path: URL path to check
    :param body: Request body to check
    :param origin_ip: IP address of the request
    :param bad_words: List of dangerous words to check against
    :param logging_function: Logging function to use (default: logging.info)
    :return: Boolean indicating if request is safe
    """
    try:
        # Decode URL path
        decoded_path = urllib.parse.unquote(path).lower()
        decoded_body = urllib.parse.unquote(body).lower() if body else ''

        # Prepare detection results
        detected_words = {
            'path': [],
            'body': []
        }
        decoded_body = decoded_body.replace("+"," ").replace("&"," ")
        print("-"*10)
        print(decoded_body)
        print("-"*10)
        # Compile regex patterns for performance
        for word in bad_words:
            # Create a precise regex pattern with word boundaries
            pattern = fr'(?<=[\s%20=]){re.escape(word.lower())}(?=[\s%20=]|$)'
            
            # Check path
            path_matches = re.findall(pattern, decoded_path)
            if path_matches:
                detected_words['path'].extend(path_matches)

            # Check body
            body_matches = re.findall(pattern, decoded_body)
            if body_matches:
                detected_words['body'].extend(body_matches)

        # If any bad words are detected
        if detected_words['path'] or detected_words['body']:
            # Detailed logging
            log_message = (
                f"Potential injection detected "
                f"IP: {origin_ip} "
                f"Path: {path} "
                f"Body: {body} "
                f"Detected in path: {detected_words['path']} "
                f"Detected in body: {detected_words['body']}"
            )
            logging_function(log_message)
            
            return False  # Block the request

        return True  # Request is safe

    except Exception as e:
        # Log any unexpected errors
        logging.error(f"Error in bad word check: {e}")
        return False  # Default to blocking in case of error

# Example usage
def validate_request(path, body, origin_ip):
    bad_words = [
        "select", "from", "where", "insert", "into", "values", 
        "' or", "or 1=1", "user()", # your list of bad words
    ]
    
    is_safe = check_for_bad_words(path, body, origin_ip, bad_words)
    return is_safe


# Function to analyze and detect threats in request data
async def analyze_request(request: Request) -> bool:
    # Extract data from request
    query_params = request.query_params
    print(query_params)
    path = request.url.path
    path += request.url.query
    body = (await request.body()).decode("utf-8") if request.method != "GET" else ""
    
    # Analyze the path and body for symbols and bad words
    path_features = analyze_string(path, "path")
    body_features = analyze_string(body, "body")
    origin_ip = get_client_ip(request)
    # Combine the features
    combined_features = {**path_features, **body_features}
    
    # Prepare the feature dataframe for prediction (matching column names)
    feature_columns = [
    'path_single_q', 'path_double_q', 'path_dashes', 'path_braces', 'path_spaces', 
    'path_percentages', 'path_semicolons', 'path_angle_brackets', 'path_special_chars', 
    'path_badwords_count', 'body_single_q', 'body_double_q', 'body_dashes', 'body_braces', 
    'body_spaces', 'body_percentages', 'body_semicolons', 'body_angle_brackets', 
    'body_special_chars', 'body_badwords_count', 'path_length', 'body_length'
    ]
    
    # Create a DataFrame for the input features
    feature_data = pd.DataFrame([combined_features], columns=feature_columns)
    feature_data.fillna(0,inplace=True)
    print("path")
    path = urllib.parse.unquote(path)
    print(path.lower())
    # Check if the path or body contains any bad words
    
    is_bad = check_for_bad_words(path,body,origin_ip,bad_words)
    if is_bad == False:
        return is_bad
    # for word in bad_words:
    #     # Create a regex pattern with word boundaries
    #     # pattern = fr'\b{re.escape(word.lower())}\b'
    #     pattern = fr'(?<=[\s%20=]){re.escape(word.lower())}(?=[\s%20=])'
    #     matches = re.findall(pattern, path.lower())
    #     print(word.lower(),matches)
    #     # Check the path
    #     if re.search(pattern, path.lower()):
    #         logging.info(f"Bad word detected in path, Request from IP: {origin_ip}, PATH: {path}, BODY: {body}, detected: {word}")
    #         return False  # Block the request
    #
    #     # Check the body
    #     if re.search(pattern, body.lower()):
    #         logging.info(f"Bad word detected in body, Request from IP: {origin_ip}, PATH: {path}, BODY: {body}, detected: {word}")
    #         return False  # Block the request
    #

    # Predict using the trained model
    prediction = model.predict(feature_data)
    print(f"prediction {prediction}")
    # If the model predicts 1 (threat detected), block the request
    # if prediction[0] == 1:
    #     logging.info(f"Threat detected based on model prediction: {combined_features} , Request from IP:{origin_ip} to PATH {path}")
    #     return False  # Block the request
    
    return True  # Allow request if no threats are detected

def analyze_string(input_string: str, source: str) -> dict:

    if re.search(r'(--.*--)', input_string):
        input_string = re.sub(r'(--.*--)', '', input_string)  # Remove multipart boundaries
    print(input_string)
    # Initialize a dictionary to hold the symbol counts
    symbols = {
        'single_q': 0, 'double_q': 0, 'dashes': 0, 'braces': 0, 'spaces': 0, 
        'percentages': 0, 'semicolons': 0, 'angle_brackets': 0, 'special_chars': 0
    }
    
    # Count occurrences of different symbols in the string
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


from typing import List, Set

def get_comprehensive_session_cookies() -> Set[str]:
    """
    Comprehensive list of session and authentication-related cookies
    from various web frameworks and technologies
    """
    session_cookies = {
        # Django
        "sessionid",
        "csrftoken",
        "django_language",
        
        # Flask
        "session",
        "remember_token",
        
        # Ruby on Rails
        "_rails_app_session",
        "rack.session",
        
        # PHP
        "phpsessid",
        "php_session",
        
        # ASP.NET
        "aspnet_session",
        ".aspnetcore_session",
        "aspnetcore_antiforgery",
        
        # Laravel
        "laravel_session",
        "laravel_token",
        
        # Express.js / Node.js
        "connect.sid",
        "express_session",
        "node_session",
        
        # Java / Spring
        "jsessionid",
        "spring_session",
        
        # Authentication Tokens
        "auth_token",
        "access_token",
        "refresh_token",
        
        # OAuth and SSO
        "oauth_token",
        "sso_token",
        
        # Authentication Providers
        "google_auth",
        "github_auth",
        "azure_auth",
        
        # Security and Identity
        "remember_me",
        "auth_session",
        "identity",
        
        # Specific Frameworks
        "symfony_session",
        "codeigniter_session",
        
        # Cloud and Distributed Systems
        "aws_session",
        "azure_session",
        
        # Misc Web Frameworks
        "sails_session",
        "meteor_session",
        
        # General Authentication
        "user_session",
        "login_token",
        "auth_cookie",
        
        # Browser-based Authentication
        "user_id",
        "logged_in",
        
        # Specific Use Cases
        "admin_session",
        "api_session",
        
        # Potential CSRF and Security Tokens
        "xsrf-token",
        "x-csrf-token",
        "csrf-token",
        
        # Tracking and Analytics (sometimes used for session-like purposes)
        "_ga",
        "_gid",
        
        # Custom and Potential Variants
        *[f"{prefix}_session" for prefix in ["custom", "app", "web", "site"]],
        *[f"{prefix}_token" for prefix in ["auth", "access", "user", "app"]]
    }
    
    # Convert to lowercase to ensure case-insensitive matching
    return {cookie.lower() for cookie in session_cookies}

from fastapi import Request, Response
import httpx
from urllib.parse import urljoin, urlparse
import logging
from http.cookies import SimpleCookie

async def proxy_request(request: Request, rde: str, req) -> Response:
    """
    Proxy request with fixed cookie handling
    """
    async with httpx.AsyncClient(follow_redirects=False) as client:
        # Get full path
        full_path = request.url.path
        if request.url.query:
            full_path = f"{full_path}?{request.url.query}"
            
        target_url = urljoin(rde, full_path)
        
        # Prepare headers
        headers = dict(request.headers)
        headers['host'] = req.source_route
        headers.pop('connection', None)
        headers.pop('transfer-encoding', None)
        
        # Fix origin and referer
        if 'origin' in headers:
            headers['origin'] = rde
        if 'referer' in headers:
            headers['referer'] = headers['referer'].replace(
                str(request.base_url).rstrip('/'), 
                rde.rstrip('/')
            )
        
        # Handle request body
        body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
            if not body and 'content-length' in headers:
                body = b''
            headers['content-length'] = str(len(body) if body else 0)
            
        logging.info(f"Proxying request to: {target_url}")
        logging.info(f"With cookies: {request.cookies}")
        
        try:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                cookies=request.cookies,
                content=body,
                follow_redirects=False
            )
            
            # Store initial response cookies
            response_cookies = SimpleCookie()
            if 'set-cookie' in response.headers:
                for cookie_str in response.headers.get_list('set-cookie'):
                    response_cookies.load(cookie_str)
            
            # Handle redirects
            if response.status_code in (301, 302, 303, 307, 308):
                redirect_url = response.headers.get('location')
                if redirect_url:
                    if not redirect_url.startswith(('http://', 'https://')):
                        redirect_url = urljoin(rde, redirect_url)
                    
                    # Update cookies for redirect
                    redirect_cookies = dict(request.cookies)
                    for key, morsel in response_cookies.items():
                        redirect_cookies[key] = morsel.value
                    
                    # Determine redirect method and body
                    if response.status_code in (307, 308):
                        redirect_method = request.method
                        redirect_body = body
                    else:
                        redirect_method = "GET"
                        redirect_body = None
                        headers['content-length'] = '0'
                    
                    response = await client.request(
                        method=redirect_method,
                        url=redirect_url,
                        headers=headers,
                        cookies=redirect_cookies,
                        content=redirect_body,
                        follow_redirects=False
                    )
                    
                    # Merge cookies from redirect response
                    if 'set-cookie' in response.headers:
                        for cookie_str in response.headers.get_list('set-cookie'):
                            response_cookies.load(cookie_str)
            
            # Prepare response
            response_headers = {
                k: v for k, v in response.headers.items()
                if k.lower() not in {'transfer-encoding', 'connection', 'keep-alive', 'set-cookie'}
            }
            
            fastapi_response = Response(
                content=response.content,
                status_code=response.status_code,
                headers=response_headers
            )
            
            # Set cookies from the final response
            for key, morsel in response_cookies.items():
                cookie_attrs = {
                    'key': key,
                    'value': morsel.value,
                    'path': morsel['path'] if 'path' in morsel else "/",
                    'httponly': bool(morsel['httponly']) if 'httponly' in morsel else True,
                    'samesite': morsel['samesite'] if 'samesite' in morsel else 'Lax'
                }
                
                # Add optional attributes
                if 'domain' in morsel:
                    cookie_attrs['domain'] = morsel['domain']
                if 'expires' in morsel:
                    cookie_attrs['expires'] = morsel['expires']
                
                if morsel.get('max-age') and morsel['max-age'].isdigit():
                    cookie_attrs['max_age'] = int(morsel['max-age'])
                else:
                    # Handle cases where 'max-age' is missing or invalid
                    cookie_attrs['max_age'] = None  # or set a default value if applicable

                if 'secure' in morsel:
                    cookie_attrs['secure'] = bool(morsel['secure'])
                
                fastapi_response.set_cookie(**cookie_attrs)
                
            logging.info(f"Response status: {response.status_code}")
            logging.info(f"Response cookies: {dict(response_cookies)}")
            
            return fastapi_response
            
        except httpx.RequestError as exc:
            logging.error(f"Proxy request failed: {exc}", exc_info=True)
            return Response(
                content=str(exc),
                status_code=500
            )
# Middleware to process requests
@app.middleware("http")
async def threat_detection_middleware(request: Request, call_next):
#
    origin_ip = get_client_ip(request)
    logging.info(f"Request received from IP: {origin_ip} to PATH: {request.url}")

    host = request.headers.get('host')
    print(host)
    req_redirect = await sync_to_async(
    lambda: RequestRedirect.objects.filter(source_route=host).first())()

    suspicious_ip = await get_suspicious_ip_async(origin_ip,req_redirect)
    suspicious_ip_exp = await is_time_expired_async(origin_ip)
    sus = False
    sus_ip = None
    is_new = False
    # Analyze the incoming request
    rde = req_redirect.good_redirect_route
    analysis = await analyze_request(request) 
    if not analysis or suspicious_ip:
        # Block request if a threat is detected 
        logging.warning(f"Blocked request from IP: {origin_ip} to PATH: {request.url}")
        # return Response("Request blocked due to security threat", status_code=403)
        if suspicious_ip or suspicious_ip_exp:
            await update_time_identified_async(origin_ip)

        else:
            print("creating")
            await create_suspicious_ip_async(origin_ip,req_redirect)
            is_new=True


        if suspicious_ip_exp:
            is_new=True
            print("fetching")
        
        sus = True
        rde = req_redirect.bad_redirect_route
        sus_ip = await fetch_suspicious_ip_async(origin_ip,req_redirect)
    
    if not suspicious_ip and suspicious_ip_exp and sus==False:
        await update_time_allowed_async(origin_ip)
    

    # Forward the request if it's safe
    
    res =  await proxy_request(request,rde,req_redirect)
    
    await create_request_log(origin_ip,req_redirect,request,sus,sus_ip,res,is_new,analysis)


    return res
    csrf_token = request.headers.get("x-csrftoken") or request.cookies.get("csrftoken")



    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Forward all headers, except the 'Host' header
        forwarded_headers = {key: value for key, value in request.headers.items() if key.lower() != ""}
        if csrf_token:
            forwarded_headers["x-csrftoken"] = csrf_token
            print(csrf_token)# Add CSRF token to headers

        # Add Referer header if missing
        if "referer" not in forwarded_headers:
            forwarded_headers["referer"] = str(request.url)

        # Build the proxied request
        forward_request = client.build_request(
            method=request.method,
            url=f"{rde}{request.url.path}",
            headers=forwarded_headers,
            params=request.query_params,
            content=await request.body(),
            cookies=request.cookies  # Forward client cookies (including csrftoken)
        )

        # Send the request to Django
        response = await client.send(forward_request)

        # Return the response to the client
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers)  # Forward Django's response headers
        )


    async with httpx.AsyncClient(follow_redirects=True) as client:
        forwarded_headers = {key: value for key, value in request.headers.items() if key.lower() != 'host'}
        forward_request = client.build_request(
            request.method, 
            f"{rde}{request.url.path}", 
            headers=forwarded_headers,#request.headers, 
            params=request.query_params, 
            content=await request.body()
        )
        response = await client.send(forward_request)
        return Response(response.content, status_code=response.status_code, headers=response.headers)

# To run the application with Uvicorn, ensure you're in the same directory as the app and use:
# uvicorn app:app --host 0.0.0.0 --port 8002
