from flask import Flask, redirect, url_for, session, request, jsonify
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from dotenv import load_dotenv
import os

app = Flask(__name__)

load_dotenv()

app.config['GLOBAL_MAP'] = {}

def set_value(key, value):
    # Set a value in the global map stored in app.config
    app.config['GLOBAL_MAP'][key] = value

def get_value(key):
    # Get a value from the global map stored in app.config
    return app.config['GLOBAL_MAP'].get(key)

GOOGLE_CLIENT_ID = os.environ.get('CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
GOOGLE_REDIRECT_URI = "http://localhost:5000/red"

@app.route('/')
def root_route():
    
    # get cookie and see if there is an active session
    # if not do google auth flow
    
    authorization_url = f'''https://accounts.google.com/o/oauth2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=openid+profile+email&state=your_random_state&prompt=consent'''
    # authorization_url, _ = flow.authorization_url(prompt='consent')
    return redirect(authorization_url)

@app.route('/red')
def redirect_route():
    state = request.args.get('state')
    code = request.args.get('code')
    print(state)
    print(code)

    token_endpoint = 'https://oauth2.googleapis.com/token'
    client_id = GOOGLE_CLIENT_ID
    client_secret = GOOGLE_CLIENT_SECRET
    redirect_uri = 'http://localhost:5000/red'

    token_payload = {
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
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

        # Print or use user information as needed
        print('User Info:', user_info)


        return jsonify(user_info)
    else:
        return jsonify({'error': 'Failed to obtain access token'})

    return 'you have been redirected'


if __name__ == '__main__':
    app.run(debug=True)