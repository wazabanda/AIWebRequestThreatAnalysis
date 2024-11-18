import pandas as pd
import joblib
import re
import numpy as np
from fastapi import FastAPI, Request, Response
import httpx
import logging
from sklearn.feature_extraction.text import TfidfVectorizer
from textblob import TextBlob  # For sentiment analysis
from nltk.tokenize import word_tokenize
from sklearn.ensemble import RandomForestClassifier
from sus import bad_words
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

all_data = pd.read_csv('./datasets/all_datas_f.csv')
tfidf_vectorizer = joblib.load('./tfidf.joblib')
to_drop = [
    'single_q', 'double_q', 'dashes', 'braces', 'spaces', 
    'percentages', 'semicolons', 'angle_brackets', 'special_chars', 
    'badwords_count','path_length','body_length'
]
all_data.drop(columns=to_drop,inplace=True)
all_data.fillna("",inplace=True)
combined_text = all_data['path'].astype(str) + " " + all_data['body'].astype(str)
# tfidf_vectorizer.fit(combined_text)

# Function to analyze and detect threats in request data
async def analyze_request(request: Request) -> bool:
    # Extract data from request
    query_params = request.query_params
    path = request.url.path
    body = (await request.body()).decode("utf-8") if request.method != "GET" else ""
    
    # Analyze the path and body for symbols and bad words
    path_length = len(path)
    path_params = path.count('=')
    path_dashes = path.count('-')
    path_braces = path.count('{') + path.count('}')
    path_spaces = path.count(' ')

    body_length = len(body)
    body_percentages = body.count('%')
    body_semicolons = body.count(';')
    body_angle_brackets = body.count('<') + body.count('>')

    body_special_chars = 0
    for char in '!@#$&*()_+=-|\\/?,.':
        if char in body:
            body_special_chars += body.count(char)

    body_badwords_count = 0
    for word in bad_words:
        body_badwords_count += body.lower().count(word.lower())

    # Load the trained model
    clf = joblib.load('malicious_request_detector.pkl')

    # Make a prediction
    X_new = [[path_length, path_params, path_dashes, path_braces, path_spaces, body_length, body_percentages, body_semicolons, body_angle_brackets, body_special_chars, body_badwords_count]]
    prediction = clf.predict(X_new)[0]

    print("prediction")
   
    print(prediction)
    # If the model predicts 1 (threat detected), block the request
    if prediction == 1:
        logging.info(f"Threat detected based on model prediction")
        return False  # Block the request
    
    return True  # Allow request if no threats are detected


# Middleware for threat detection
@app.middleware("http")
async def threat_detection_middleware(request: Request, call_next):
    query_params = request.query_params
    # path = request.url.path
    # body = (await request.body()).decode("utf-8") if request.method != "GET" else ""

  
    if not (await analyze_request(request)):
        return Response("Request blocked due to detected threat.", status_code=403)

    # Forward request if safe
    async with httpx.AsyncClient() as client:
        forward_request = client.build_request(
            request.method, f"http://localhost:8001{request.url.path}",
            headers=request.headers, params=request.query_params, content=await request.body()
        )
        response = await client.send(forward_request)
        return Response(response.content, status_code=response.status_code, headers=response.headers)

# To run the application with Uvicorn, ensure you're in the same directory as the app and use:
# uvicorn app:app --host 0.0.0.0 --port 8002
