import re
import pandas as pd
import joblib  # or any other model loading mechanism
from fastapi import FastAPI, Request, Response
import httpx
import logging

# Initialize FastAPI app
app = FastAPI()

# Destination URL (web application)
DESTINATION_URL = "http://localhost:8001"  # Modify to your web application's URL

# Logging setup
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app_logs.log"),  # Log to file 'app_logs.log'
        logging.StreamHandler()  # Also output logs to console
    ]
)
# Load the machine learning model (ensure this is the correct path to your model file)
model = joblib.load("./request_threat_model.pkl")  # Modify with the correct path to your saved model

# List of bad words (from PHP, JavaScript, Python, etc.)
bad_words = [
    "select", "insert", "update", "delete", "union", "drop", "eval", "exec", "base64_decode", 
    "system", "shell", "phpinfo", "alert", "document.cookie", "exec", "os.system", "os.popen"
]

# Function to analyze and detect threats in request data
async def analyze_request(request: Request) -> bool:
    # Extract data from request
    query_params = request.query_params
    path = request.url.path
    body = (await request.body()).decode("utf-8") if request.method != "GET" else ""
    
    # Analyze the path and body for symbols and bad words
    path_features = analyze_string(path, "path")
    body_features = analyze_string(body, "body")
    
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
    print(body)
    print(feature_data)
    # # Check if the path or body contains any bad words
    # if any(word.lower() in path.lower() for word in bad_words) or \
    #    any(word.lower() in body.lower() for word in bad_words):
    #     logging.info(f"Bad word detected in path or body")
    #     return False  # Block the request

    # Predict using the trained model
    prediction = model.predict(feature_data)
    print(f"prediction {prediction}")
    # If the model predicts 1 (threat detected), block the request
    if prediction[0] == 1:
        logging.info(f"Threat detected based on model prediction: {combined_features}")
        return False  # Block the request
    
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

# Middleware to process requests
@app.middleware("http")
async def threat_detection_middleware(request: Request, call_next):
    # Analyze the incoming request
    if not await analyze_request(request):
        # Block request if a threat is detected
        logging.warning(f"Blocked request to {request.url}")
        return Response("Request blocked due to security threat", status_code=403)

    # Forward the request if it's safe
    async with httpx.AsyncClient() as client:
        forward_request = client.build_request(
            request.method, 
            f"{DESTINATION_URL}{request.url.path}", 
            headers=request.headers, 
            params=request.query_params, 
            content=await request.body()
        )
        response = await client.send(forward_request)
        return Response(response.content, status_code=response.status_code, headers=response.headers)

# To run the application with Uvicorn, ensure you're in the same directory as the app and use:
# uvicorn app:app --host 0.0.0.0 --port 8002
