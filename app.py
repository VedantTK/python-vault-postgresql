import psycopg2
import requests
import configparser
import base64
import logging
from flask import Flask, request, render_template_string

# Configure logging to file and console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler('/tmp/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load config
config = configparser.ConfigParser()
config.read('config.ini')
VAULT_ADDR = config['Vault']['vault_addr']
VAULT_TOKEN = config['Vault']['vault_token']
VAULT_DB_CREDS_PATH = config['Vault']['db_path']
ENCRYPTION_KEY = config['Vault']['encryption_key']
DB_HOST = config['Database']['host']
DB_PORT = config['Database']['port']
DB_NAME = config['Database']['dbname']

# Test Vault connectivity
try:
    response = requests.get(f"{VAULT_ADDR}/v1/sys/health", headers={'X-Vault-Token': VAULT_TOKEN})
    logger.info(f"Vault health check: {response.status_code}")
except Exception as e:
    logger.error(f"Vault connectivity test failed: {str(e)}")

# Fetch dynamic DB credentials from Vault
def get_db_credentials():
    logger.debug(f"Fetching credentials from {VAULT_ADDR}/v1/{VAULT_DB_CREDS_PATH}")
    try:
        url = f"{VAULT_ADDR}/v1/{VAULT_DB_CREDS_PATH}"
        headers = {'X-Vault-Token': VAULT_TOKEN}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        logger.debug(f"Credentials fetched: {data['data']['username']}")
        return data['data']['username'], data['data']['password']
    except Exception as e:
        logger.error(f"Failed to fetch DB credentials: {str(e)}")
        raise

# Encrypt using Vault transit
def vault_encrypt(plaintext):
    logger.debug(f"Encrypting data with key {ENCRYPTION_KEY}: {plaintext}")
    try:
        url = f"{VAULT_ADDR}/v1/transit/encrypt/{ENCRYPTION_KEY}"
        headers = {
            'X-Vault-Token': VAULT_TOKEN,
            'Content-Type': 'application/json'
        }
        b64_encoded = base64.b64encode(plaintext.encode('utf-8')).decode('utf-8')
        payload = {'plaintext': b64_encoded}
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        ciphertext = response.json()['data']['ciphertext']
        logger.debug(f"Encrypted data: {ciphertext}")
        return ciphertext
    except Exception as e:
        logger.error(f"Encryption failed for '{plaintext}': {str(e)}")
        raise

# Decrypt using Vault transit
def vault_decrypt(ciphertext):
    logger.debug(f"Decrypting data: {ciphertext}")
    try:
        url = f"{VAULT_ADDR}/v1/transit/decrypt/{ENCRYPTION_KEY}"
        headers = {
            'X-Vault-Token': VAULT_TOKEN,
            'Content-Type': 'application/json'
        }
        payload = {'ciphertext': ciphertext}
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        plaintext_b64 = response.json()['data']['plaintext']
        plaintext = base64.b64decode(plaintext_b64).decode('utf-8')
        logger.debug(f"Decrypted data: {plaintext}")
        return plaintext
    except Exception as e:
        logger.error(f"Decryption failed for '{ciphertext}': {str(e)}")
        raise

# Encode (mask) SSN using Vault Transform (retained but unused for now)
def vault_transform_encode_ssn(ssn_value):
    logger.debug(f"Encoding SSN: {ssn_value}")
    try:
        url = f"{VAULT_ADDR}/v1/transform/encode/masking-role"
        headers = {
            'X-Vault-Token': VAULT_TOKEN,
            'Content-Type': 'application/json'
        }
        payload = {
            "value": ssn_value,
            "transformation": "ssn-fpe"
        }
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        encoded_value = response.json()['data']['encoded_value']
        logger.debug(f"Encoded SSN: {encoded_value}")
        return encoded_value
    except Exception as e:
        logger.error(f"SSN encoding failed: {str(e)}")
        raise

# Decode (unmask) SSN using Vault Transform (retained but unused for now)
def vault_transform_decode_ssn(encoded_value):
    logger.debug(f"Decoding SSN: {encoded_value}")
    try:
        url = f"{VAULT_ADDR}/v1/transform/decode/masking-role/last-four"
        headers = {
            'X-Vault-Token': VAULT_TOKEN,
            'Content-Type': 'application/json'
        }
        payload = {
            "value": encoded_value,
            "transformation": "ssn-fpe"
        }
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        decoded_value = response.json()['data']['decoded_value']
        logger.debug(f"Decoded SSN: {decoded_value}")
        return decoded_value
    except Exception as e:
        logger.error(f"SSN decoding failed: {str(e)}")
        raise

# Encode (mask) phone number using Vault Transform (retained but unused for now)
def vault_transform_encode_phone(phone_value):
    logger.debug(f"Encoding phone number: {phone_value}")
    try:
        url = f"{VAULT_ADDR}/v1/transform/encode/masking-role"
        headers = {
            'X-Vault-Token': VAULT_TOKEN,
            'Content-Type': 'application/json'
        }
        payload = {
            "value": phone_value,
            "transformation": "phone-fpe"
        }
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        encoded_value = response.json()['data']['encoded_value']
        logger.debug(f"Encoded phone number: {encoded_value}")
        return encoded_value
    except Exception as e:
        logger.error(f"Phone number encoding failed: {str(e)}")
        raise

# Decode (unmask) phone number using Vault Transform (retained but unused for now)
def vault_transform_decode_phone(encoded_value):
    logger.debug(f"Decoding phone number: {encoded_value}")
    try:
        url = f"{VAULT_ADDR}/v1/transform/decode/masking-role/full"
        headers = {
            'X-Vault-Token': VAULT_TOKEN,
            'Content-Type': 'application/json'
        }
        payload = {
            "value": encoded_value,
            "transformation": "phone-fpe"
        }
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        decoded_value = response.json()['data']['decoded_value']
        logger.debug(f"Decoded phone number: {decoded_value}")
        return decoded_value
    except Exception as e:
        logger.error(f"Phone number decoding failed: {str(e)}")
        raise

# Connect to PostgreSQL with dynamic credentials
def get_db_connection():
    username, password = get_db_credentials()
    logger.debug(f"Connecting to database with user {username}")
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=username,
            password=password
        )
        logger.debug("Database connection successful")
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {str(e)}")
        raise

# Flask app setup
app = Flask(__name__)

base_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Vault</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Helvetica Neue', Arial, sans-serif;
            background-color: #FFFFFF;
            color: #000000;
            line-height: 1.6;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .navbar {
            background-color: #000000;
            padding: 1rem;
            text-align: center;
            position: relative;
        }
        .navbar a {
            color: #FFFFFF;
            text-decoration: none;
            font-weight: 500;
            font-size: 1.1rem;
            margin: 0 1.5rem;
            position: relative;
            transition: color 0.3s;
        }
        .navbar a::after {
            content: '';
            position: absolute;
            width: 0;
            height: 2px;
            background-color: #FFFFFF;
            bottom: -4px;
            left: 0;
            transition: width 0.3s ease;
        }
        .navbar a:hover::after, .navbar a.active::after {
            width: 100%;
        }
        .navbar-title {
            position: absolute;
            right: 1rem;
            top: 50%;
            transform: translateY(-50%);
            font-size: 1.2rem;
            font-weight: 700;
            color: #FFFFFF;
        }
        .content {
            padding: 2rem;
            max-width: 900px;
            margin: 0 auto;
            flex: 1;
        }
        .form-container {
            background-color: #FFFFFF;
            padding: 2rem;
            border: 2px solid #000000;
            border-radius: 16px;
            max-width: 400px;
            margin: 2rem auto;
            max-height: 70vh;
            overflow-y: auto;
            transition: box-shadow 0.3s;
        }
        .form-container:hover {
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            font-weight: 600;
            font-size: 1rem;
            margin-bottom: 0.5rem;
            display: block;
        }
        input[type="text"], input[type="email"], input[type="tel"] {
            width: 100%;
            padding: 0.8rem;
            border: 2px solid #000000;
            border-radius: 8px;
            font-size: 1rem;
            background-color: #FFFFFF;
            color: #000000;
            transition: border-color 0.3s, transform 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #4A4A4A;
            transform: scale(1.02);
        }
        input[type="submit"] {
            background-color: #000000;
            color: #FFFFFF;
            padding: 0.8rem;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1.1rem;
            font-weight: 600;
            width: 100%;
            transition: background-color 0.3s, transform 0.2s;
        }
        input[type="submit"]:hover {
            background-color: #4A4A4A;
            transform: translateY(-2px);
        }
        .table-container {
            overflow-x: auto;
            border: 2px solid #000000;
            border-radius: 16px;
            margin-top: 2rem;
            transition: box-shadow 0.3s;
        }
        .table-container:hover {
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: #FFFFFF;
        }
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #000000;
        }
        th {
            background-color: #000000;
            color: #FFFFFF;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        tr:hover {
            background-color: #F2F2F2;
        }
        td {
            word-break: break-word;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .message {
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 8px;
            font-weight: 500;
            text-align: center;
        }
        .success {
            background-color: #E5E5E5;
            color: #000000;
        }
        .error {
            background-color: #FFD1D1;
            color: #000000;
        }
        .loading {
            text-align: center;
            padding: 2rem;
            color: #4A4A4A;
        }
        .footer {
            background-color: #000000;
            color: #FFFFFF;
            text-align: center;
            padding: 1rem;
            font-size: 0.9rem;
        }
        @media (max-width: 768px) {
            .content {
                padding: 1rem;
            }
            .navbar {
                padding: 0.5rem;
            }
            .navbar a {
                margin: 0 0.5rem;
                font-size: 1rem;
            }
            .navbar-title {
                font-size: 1rem;
            }
            th, td {
                padding: 0.75rem;
                font-size: 0.9rem;
            }
            td {
                max-width: 150px;
            }
            .form-container {
                max-height: 60vh;
                padding: 1.5rem;
            }
        }
        @media (max-width: 480px) {
            .navbar a {
                font-size: 0.9rem;
                margin: 0 0.3rem;
            }
            th, td {
                font-size: 0.85rem;
                padding: 0.5rem;
            }
            td {
                max-width: 100px;
            }
            input[type="submit"] {
                padding: 0.75rem;
            }
            .form-container {
                max-width: 100%;
                margin: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="navbar">
        <a href="{{ url_for('add_employee') }}" {% if request.path == '/' %}class="active"{% endif %}>Add Employee</a>
        <a href="{{ url_for('view_employees') }}" {% if request.path == '/employees' %}class="active"{% endif %}>View Employees</a>
        <a href="{{ url_for('view_encrypted_employees') }}" {% if request.path == '/employees/encrypted' %}class="active"{% endif %}>Encrypted View</a>
        <div class="navbar-title">HashiCorp Vault Demo</div>
    </div>
    <div class="content">
        {{ content|safe }}
    </div>
    <div class="footer">
        &copy; 2025 Employee Vault | Built with Flask
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def add_employee():
    msg = ''
    if request.method == 'POST':
        name = request.form['name']
        role = request.form['role']
        email = request.form['email']
        phone = request.form['phone']
        ssn = request.form['ssn']
        address = request.form['address']
        
        # Basic input validation
        if not all([name, role, email, phone, ssn, address]):
            msg = '<div class="message error">All fields are required!</div>'
        else:
            conn = None
            cur = None
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                
                # Encrypt all sensitive fields using Transit
                encrypted_email = vault_encrypt(email)
                encrypted_phone = vault_encrypt(phone)
                encrypted_ssn = vault_encrypt(ssn)
                encrypted_address = vault_encrypt(address)
                
                logger.debug(f"Inserting employee: {name}, {role}, {encrypted_email}, {encrypted_phone}, {encrypted_ssn}, {encrypted_address}")
                cur.execute("INSERT INTO employees (id, name, role, email, phone_number, ssn, address) VALUES (DEFAULT, %s, %s, %s, %s, %s, %s) RETURNING id",
                           (name, role, encrypted_email, encrypted_phone, encrypted_ssn, encrypted_address))
                emp_id = cur.fetchone()[0]
                conn.commit()
                logger.info(f"Employee {name} added successfully with ID {emp_id}")
                msg = f'<div class="message success">Employee {name} added successfully with ID {emp_id}!</div>'
            except Exception as e:
                logger.error(f"Error adding employee: {str(e)}")
                msg = f'<div class="message error">Error: {str(e)}</div>'
                if conn:
                    conn.rollback()
            finally:
                if cur:
                    cur.close()
                if conn:
                    conn.close()

    form_html = '''
    <h2>Add Employee</h2>
    <div class="form-container">
        <form method="POST">
            <div class="form-group">
                <label for="name">Name</label>
                <input type="text" name="name" id="name" required placeholder="Enter Name">
            </div>
            <div class="form-group">
                <label for="role">Role</label>
                <input type="text" name="role" id="role" required placeholder="Enter Role">
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" name="email" id="email" required placeholder="Enter Email">
            </div>
            <div class="form-group">
                <label for="phone">Phone</label>
                <input type="tel" name="phone" id="phone" required placeholder="Enter Phone (10 digits)">
            </div>
            <div class="form-group">
                <label for="ssn">SSN</label>
                <input type="text" name="ssn" id="ssn" required placeholder="Enter SSN (9 digits)">
            </div>
            <div class="form-group">
                <label for="address">Address</label>
                <input type="text" name="address" id="address" required placeholder="Enter Address">
            </div>
            <input type="submit" value="Add Employee">
        </form>
    </div>
    '''
    return render_template_string(base_template, content=msg + form_html)

@app.route('/employees')
def view_employees():
    content = '<div class="loading">Loading employee records...</div>'
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM employees")
        rows = cur.fetchall()
        headers = [desc[0] for desc in cur.description]
        
        # Decrypt all sensitive fields using Transit
        decrypted_rows = []
        for row in rows:
            decrypted_row = list(row)
            try:
                decrypted_row[3] = vault_decrypt(row[3]) if row[3].startswith('vault:v1:') else row[3]
                decrypted_row[4] = vault_decrypt(row[4]) if row[4].startswith('vault:v1:') else row[4]
                decrypted_row[5] = vault_decrypt(row[5]) if row[5].startswith('vault:v1:') else row[5]
                decrypted_row[6] = vault_decrypt(row[6]) if row[6].startswith('vault:v1:') else row[6]
            except Exception as e:
                logger.error(f"Decryption error for row {row[0]}: {str(e)}")
                decrypted_row[3] = row[3]  # Keep original value if decryption fails
                decrypted_row[4] = row[4]
                decrypted_row[5] = row[5]
                decrypted_row[6] = row[6]
            decrypted_rows.append(decrypted_row)
        
        content = '''
        <h2>Employee Records</h2>
        <div class="table-container">
            <table>
                <tr>{}</tr>
                {}
            </table>
        </div>
        '''.format(
            ''.join([f'<th>{h}</th>' for h in headers]),
            ''.join(['<tr>' + ''.join([f'<td title="{str(col)}">{str(col)}</td>' for col in row]) + '</tr>' for row in decrypted_rows])
        )
    except Exception as e:
        logger.error(f"Error fetching employees: {str(e)}")
        content = f'<div class="message error">Error fetching data: {str(e)}</div>'
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return render_template_string(base_template, content=content)

@app.route('/employees/encrypted')
def view_encrypted_employees():
    content = '<div class="loading">Loading encrypted employee records...</div>'
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM employees")
        rows = cur.fetchall()
        headers = [desc[0] for desc in cur.description]

        content = '''
        <h2>Encrypted Employee Records</h2>
        <div class="table-container">
            <table>
                <tr>{}</tr>
                {}
            </table>
        </div>
        '''.format(
            ''.join([f'<th>{h}</th>' for h in headers]),
            ''.join(['<tr>' + ''.join([f'<td title="{str(col)}">{str(col)}</td>' for col in row]) + '</tr>' for row in rows])
        )
    except Exception as e:
        logger.error(f"Error fetching encrypted employees: {str(e)}")
        content = f'<div class="message error">Error fetching data: {str(e)}</div>'
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return render_template_string(base_template, content=content)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
