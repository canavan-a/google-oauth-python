from flask import Flask, redirect, url_for, session, request, jsonify, make_response
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from dotenv import load_dotenv
import uuid
import os

app = Flask(__name__)

load_dotenv()

app.config['SESSION_MAP'] = {}

def set_value(key, value):
    # Set a value in the global map stored in app.config
    app.config['SESSION_MAP'][key] = value

def get_value(key):
    # Get a value from the global map stored in app.config
    return app.config['SESSION_MAP'].get(key)

GOOGLE_CLIENT_ID = os.environ.get('CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
GOOGLE_REDIRECT_URI = "http://localhost:5000/red"
LANDING_URL = "https://picstone-generative-ai.vercel.app/"

@app.route('/get_google_oauth_link')
def root_route():
    
    # get cookie and see if there is an active session
    session_token = request.cookies.get('session_token')
    
    if not session_token:
    
        authorization_url = f'''https://accounts.google.com/o/oauth2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=openid+profile+email&prompt=consent'''
        return authorization_url
    else:
        map_value = get_value(session_token)
        if not map_value:
            authorization_url = f'''https://accounts.google.com/o/oauth2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=openid+profile+email&prompt=consent'''
            return authorization_url
        print(map_value)
        return f"user already has active session {map_value}"

@app.route('/red')
def redirect_route():
    code = request.args.get('code')

    token_endpoint = 'https://oauth2.googleapis.com/token'

    token_payload = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }

    token_response = requests.post(token_endpoint, data=token_payload)
    token_data = token_response.json()

    access_token = token_data.get('access_token')
    if access_token:

        user_info_endpoint = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}

        # Retrieve user information
        user_info_response = requests.get(user_info_endpoint, headers=headers)
        user_info = user_info_response.json()

        session_token = str(uuid.uuid4())
        
        response = make_response(f'''
                            <!DOCTYPE html>
                            <html lang="en">
                            <head>
                                <meta charset="UTF-8">
                                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Redirect Example</title>
                            </head>
                            <body>

                            <script>
                                // JavaScript code to redirect to another page
                                window.location.href = '{LANDING_URL}';  // Replace with your desired URL
                            </script>

                            </body>
                            </html>
                            ''')

        response.set_cookie('session_token',
                                session_token,
                                httponly=True,
                                max_age=1000)
        
        # add session to global list
        set_value(session_token, str(user_info['email']))

        return response
    else:
        return jsonify({'error': 'Failed to obtain access token'})


if __name__ == '__main__':
    app.run(debug=True)