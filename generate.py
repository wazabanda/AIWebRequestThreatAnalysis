import pandas as pd
import random

# Define a list of common attack patterns for malicious requests
malicious_paths = [
    "/admin?username=admin' OR '1'='1&password=1234",
    "/login.php?user=root&pass=secret' OR 1=1;--",
    "/search?q=<script>alert('xss')</script>",
    "/upload?file=../../../../etc/passwd",
    "/api/v1/users;DROP TABLE users;",
]

malicious_bodies = [
    "{ 'username': 'admin', 'password': 'password123' OR '1'='1' }",
    '{"data": "<script>alert(\'XSS\')</script>"}',
    '{"user": "guest", "action": "delete", "target": "/var/log"}',
    "username=admin'--&password=foo",
    '{"search": "DROP TABLE users;"}'
]

# Define benign paths and bodies (safe formats)
benign_paths = [
    "/home", "/profile", "/about", "/products?id=1234",
    "/contact?email=test@example.com"
]

benign_bodies = [
    '{"name": "Alice", "message": "Hello, world!"}',
    '{"product": "laptop", "price": "1200"}',
    '{"comment": "This is a great product!"}',
    "username=guest&password=123456",
    '{"search": "normal query"}'
]

# Define function to create synthetic dataset
def generate_synthetic_requests(num_benign=100, num_malicious=100):
    data = []

    # Generate benign requests
    for _ in range(num_benign):
        path = random.choice(benign_paths)
        body = random.choice(benign_bodies)
        entry = {
            "method": random.choice(["GET", "POST"]),
            "path": path,
            "body": body,
            "single_q": body.count("'"),
            "double_q": body.count('"'),
            "dashes": path.count('-'),
            "braces": path.count('{') + path.count('}'),
            "spaces": path.count(' '),
            "percentages": body.count('%'),
            "semicolons": body.count(';'),
            "angle_brackets": body.count('<') + body.count('>'),
            "special_chars": sum([body.count(c) for c in "!@#$&*()_+=-|\\/?,."]),
            "path_length": len(path),
            "body_length": len(body),
            "badwords_count": 0,
            "class": 0  # Benign
        }
        data.append(entry)

    # Generate malicious requests
    for _ in range(num_malicious):
        path = random.choice(malicious_paths)
        body = random.choice(malicious_bodies)
        entry = {
            "method": random.choice(["GET", "POST"]),
            "path": path,
            "body": body,
            "single_q": body.count("'"),
            "double_q": body.count('"'),
            "dashes": path.count('-'),
            "braces": path.count('{') + path.count('}'),
            "spaces": path.count(' '),
            "percentages": body.count('%'),
            "semicolons": body.count(';'),
            "angle_brackets": body.count('<') + body.count('>'),
            "special_chars": sum([body.count(c) for c in "!@#$&*()_+=-|\\/?,."]),
            "path_length": len(path),
            "body_length": len(body),
            "badwords_count": sum(word in body for word in ["drop", "delete", "alert", "select", "insert"]),
            "class": 1  # Malicious
        }
        data.append(entry)

    return pd.DataFrame(data)

# Example usage:
df = generate_synthetic_requests(num_benign=750, num_malicious=250)
print(df.head())


# Save the dataset
df.to_csv("synthetic_malicious_requests_with_json.csv", index=False)
