import os
import time
import base64
import logging
from flask import Flask, render_template, request, redirect, session, jsonify, url_for
import requests
from urllib.parse import urlencode
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY').encode()  # Ensure bytes for secret key

# Configure requests session with retry strategy
session_retry = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504]
)
session_retry.mount("https://", HTTPAdapter(max_retries=retry_strategy))

# Spotify API configuration
CLIENT_ID = os.getenv('SPOTIFY_CLIENT_ID')
CLIENT_SECRET = os.getenv('SPOTIFY_CLIENT_SECRET')
REDIRECT_URI = os.getenv('SPOTIFY_REDIRECT_URI')

# Spotify API endpoints
AUTH_URL = 'https://accounts.spotify.com/authorize'
TOKEN_URL = 'https://accounts.spotify.com/api/token'
API_BASE_URL = 'https://api.spotify.com/v1'

# Helper functions
def create_auth_header():
    auth_str = f"{CLIENT_ID}:{CLIENT_SECRET}"
    return {
        'Authorization': f'Basic {base64.b64encode(auth_str.encode()).decode()}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

def validate_session():
    if 'access_token' not in session:
        return False
    if time.time() > session.get('expires_at', 0) - 300:  # Refresh if expires in 5 min
        return refresh_access_token()
    return True

def refresh_access_token():
    if 'refresh_token' not in session:
        return False
    
    try:
        response = session_retry.post(
            TOKEN_URL,
            headers=create_auth_header(),
            data={
                'grant_type': 'refresh_token',
                'refresh_token': session['refresh_token']
            }
        )
        if response.status_code == 200:
            token_data = response.json()
            session.update({
                'access_token': token_data['access_token'],
                'expires_at': time.time() + token_data['expires_in']
            })
            return True
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
    
    return False

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check-auth')
def check_auth():
    return jsonify({
        'authenticated': 'access_token' in session,
        'username': session.get('display_name', 'User')
    })

@app.route('/login')
def login():
    scope = 'user-modify-playback-state user-read-playback-state user-read-private'
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'scope': scope,
        'redirect_uri': REDIRECT_URI,
        'show_dialog': True
    }
    return redirect(f"{AUTH_URL}?{urlencode(params)}")

@app.route('/callback')
def callback():
    if 'error' in request.args:
        return jsonify({"error": request.args['error']}), 400
    
    if 'code' not in request.args:
        return redirect(url_for('login'))

    try:
        # Exchange code for token
        response = session_retry.post(
            TOKEN_URL,
            headers=create_auth_header(),
            data={
                'grant_type': 'authorization_code',
                'code': request.args['code'],
                'redirect_uri': REDIRECT_URI
            }
        )
        
        if response.status_code != 200:
            error = response.json().get('error_description', 'Token exchange failed')
            return jsonify({"error": error}), 400
        
        token_data = response.json()
        session.update({
            'access_token': token_data['access_token'],
            'refresh_token': token_data.get('refresh_token', session.get('refresh_token')),
            'expires_at': time.time() + token_data['expires_in']
        })

        # Get user info
        user_info = session_retry.get(
            f"{API_BASE_URL}/me",
            headers={'Authorization': f"Bearer {session['access_token']}"}
        ).json()
        
        session['display_name'] = user_info.get('display_name', 'User')
        return redirect(url_for('index'))

    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/search')
def search():
    if not validate_session():
        return jsonify({"error": "Authentication required"}), 401

    query = request.args.get('q')
    if not query:
        return jsonify({"error": "Missing query"}), 400

    try:
        response = session_retry.get(
            f"{API_BASE_URL}/search",
            headers={'Authorization': f"Bearer {session['access_token']}"},
            params={
                "q": query,
                "type": "track",
                "limit": 5
            }
        )
        response.raise_for_status()
        
        tracks = response.json().get('tracks', {}).get('items', [])
        return jsonify([{
            "name": track["name"],
            "artist": track["artists"][0]["name"],
            "uri": track["uri"],
            "image": track["album"]["images"][0]["url"] if track["album"]["images"] else None
        } for track in tracks])

    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/queue', methods=['POST'])
def queue_track():
    if not validate_session():
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    if not data or 'uri' not in data:
        return jsonify({"error": "Missing track URI"}), 400

    try:
        # 1. Check for active devices first
        devices_response = requests.get(
            f"{API_BASE_URL}/me/player/devices",
            headers={'Authorization': f"Bearer {session['access_token']}"},
            timeout=5
        )
        
        # Handle empty or invalid response
        if not devices_response.content:
            return jsonify({
                "error": "Empty response from Spotify",
                "solution": "Try again in a moment"
            }), 502

        devices_data = devices_response.json()
        if not devices_data.get('devices'):
            return jsonify({
                "error": "No active devices",
                "solution": "Open Spotify on any device and start playback"
            }), 404

        # 2. Queue the track
        queue_response = requests.post(
            f"{API_BASE_URL}/me/player/queue?uri={data['uri']}",
            headers={'Authorization': f"Bearer {session['access_token']}"},
            timeout=5
        )

        # Successful queue (204 No Content)
        if queue_response.status_code == 204:
            return jsonify({
                "success": True,
                "message": "Track added to queue successfully"
            })

        # Handle other responses
        try:
            error_data = queue_response.json()
            return jsonify({
                "error": error_data.get('error', {}).get('message', 'Queue failed'),
                "status": queue_response.status_code
            }), queue_response.status_code
        except ValueError:
            return jsonify({
                "error": "Unexpected response from Spotify",
                "status": queue_response.status_code
            }), queue_response.status_code

    except requests.exceptions.Timeout:
        return jsonify({
            "error": "Request timed out",
            "solution": "Check your network connection"
        }), 504
    except requests.exceptions.RequestException as e:
        return jsonify({
            "error": "Network error",
            "details": str(e),
            "solution": "Check your internet connection"
        }), 503
    except Exception as e:
        return jsonify({
            "error": "Unexpected error",
            "details": str(e)
        }), 500