#Kaylyn King
#CSCE 3550
#kaylynking@my.unt.edu
#3/23/24
#Project 2
from flask import Flask, jsonify, request
import jwt, base64, secrets
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

#Array to hold keys
keyArray = {}

def start_database():

    try:
        conn = sqlite3.connect("totally_not_my_privateKeys.db")    
    except Exception as e:
        print(e)

    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    expiry INTEGER NOT NULL
                    )''')

    conn.commit()
    conn.close()

def write_key_to_db(key, expiry):
    try:
        print("connecting to database in write_key_to_db")
        conn = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = conn.cursor()
        cursor.execute('''INSERT OR REPLACE INTO keys (key, expiry)
                     VALUES (?, ?)''', (key, expiry))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print("Error writing to database:", e)

def get_key_from_db(kid):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''SELECT key FROM keys WHERE kid = ?''', (kid,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result[0]
    else:
        return None

#generate a rsa key pair
def generate_rsa_key_pair(expiry_duration=1800): #set expiration to 30 min
        #create a random kid

        #generate a private key via rsa import
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()).decode('utf-8')

        # write private key to the database
        expiry_time = datetime.now(timezone.utc) + timedelta(seconds=expiry_duration)
        write_key_to_db(private_key_pem, int(expiry_time.timestamp()))


#encode the 'n', 'e' public key components in base64url for JWK response format
def encode_key_value(key):
    return base64.urlsafe_b64encode(key.to_bytes((key.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")

def get_public_keys_from_db():
    try:
        print("getting keys from database")
        current_time = datetime.now(timezone.utc)
        conn = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT kid, key, expiry FROM keys WHERE expiry > ?''', (int(current_time.timestamp()),))
        rows = cursor.fetchall()
        conn.close()
        keys = []
        for row in rows:
            private_key = serialization.load_pem_private_key(
                row[1],
                password = None,
                backend = default_backend()
            )

            public_key = private_key.public_key()

            keys.append({
                'kty': 'RSA',
                'alg': 'RS256',
                'kid': str(row[0]),
                'use': 'sig',
                'n': encode_key_value(public_key.public_numbers().n),
                'e': encode_key_value(public_key.public_numbers().e),
                'exp': int(row[2])
            })
        return keys
    except sqlite3.Error as e:
        print("Error writing to database:", e)

#create and return JWKS response
@app.route('/.well-known/jwks.json' , methods=['GET'])
def jwks():
        #create JWK for valid keys
        keys = get_public_keys_from_db()
        return jsonify({'keys': keys})

#filters through keyArray and returns key based on given 'expired' condition 
def get_selected_kid(expired):
    current_time = datetime.now(timezone.utc)
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''SELECT kid FROM keys WHERE expiry > ?''' if not expired else '''SELECT kid FROM keys WHERE expiry < ?''', (int(current_time.timestamp()),))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    else:
        return None

#issues JWTs
@app.route('/auth', methods=['POST'])
def auth():
    # determines if request is for expired keys
    expired = 'expired' in request.args

    # find the key if present in database based on conditions otherwise generate key based on conditions
    temp = get_selected_kid(expired) or generate_rsa_key_pair(-1800 if expired else 1800)

    # retrieve key from database
    key = get_key_from_db(temp)

    # create JWT payload with issuance time and expiration time based on conditions
    payload = {
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(seconds=1800 if not expired else -1800)
    }

    # create JWT with key pair
    token = jwt.encode(payload,
                       key,
                       algorithm='RS256',
                       headers={'kid': str(temp)})

    return jsonify({'token': token})

#generate key and run app
if __name__ == '__main__':
        start_database()
        generate_rsa_key_pair()
        app.run(port=8080, debug=True)

