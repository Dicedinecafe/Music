import warnings
from urllib3.exceptions import NotOpenSSLWarning
warnings.filterwarnings("ignore", category=NotOpenSSLWarning)

import os
import time
import base64
import logging
from flask import Flask, render_template, request, jsonify
import requests
from urllib.parse import urlencode
#from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Load environment variables
#load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY').encode()

# Spotify credentials
CLIENT_ID = os.getenv('SPOTIFY_CLIENT_ID')
CLIENT_SECRET = os.getenv('SPOTIFY_CLIENT_SECRET')
REFRESH_TOKEN = os.getenv('SPOTIFY_REFRESH_TOKEN')

# Spotify endpoints
TOKEN_URL = 'https://accounts.spotify.com/api/token'
API_BASE_URL = 'https://api.spotify.com/v1'

# Requests session with retries
session_retry = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504]
)
session_retry.mount("https://", HTTPAdapter(max_retries=retry_strategy))
print("ENV TEST:", os.getenv('SPOTIFY_CLIENT_ID'), os.getenv('FLASK_SECRET_KEY'))

# Get access token using refresh token
def get_access_token():
    try:
        auth_str = f"{CLIENT_ID}:{CLIENT_SECRET}"
        headers = {
            'Authorization': f'Basic {base64.b64encode(auth_str.encode()).decode()}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': REFRESH_TOKEN
        }
        response = session_retry.post(TOKEN_URL, headers=headers, data=data)
        response.raise_for_status()
        token_data = response.json()
        return token_data['access_token']
    except Exception as e:
        logger.error(f"Access token retrieval failed: {str(e)}")
        return None

# Home route
@app.route('/')
def index():
    return render_template('index.html')  # Make sure to create a simple index.html for UI
@app.route('/current')
def current_playing():
    access_token = get_access_token()
    if not access_token:
        return jsonify({"error": "Failed to authorize with Spotify"}), 500
    try:
        response = session_retry.get(
            f"{API_BASE_URL}/me/player/currently-playing",
            headers={'Authorization': f"Bearer {access_token}"}
        )
        if response.status_code == 204:
            return jsonify({"message": "No track currently playing"}), 204
        response.raise_for_status()
        data = response.json()
        if not data or "item" not in data:
            return jsonify({"message": "No track currently playing"}), 204
        track = data["item"]
        current_track = {
            "name": track["name"],
            "artist": track["artists"][0]["name"],
            "image": track["album"]["images"][0]["url"] if track["album"]["images"] else None,
            "uri": track["uri"],
            "progress_ms": data.get("progress_ms", 0),
            "duration_ms": track.get("duration_ms", 0),
            "is_playing": data.get("is_playing", False),
        }
        return jsonify(current_track)
    except Exception as e:
        logger.error(f"Current track error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Search route
@app.route('/search')
def search():
    query = request.args.get('q')
    if not query:
        return jsonify({"error": "Missing query"}), 400

    access_token = get_access_token()
    if not access_token:
        return jsonify({"error": "Failed to authorize with Spotify"}), 500

    try:
        response = session_retry.get(
            f"{API_BASE_URL}/search",
            headers={'Authorization': f"Bearer {access_token}"},
            params={"q": query, "type": "track", "limit": 5}
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

# Queue track route
@app.route('/queue', methods=['POST'])
def queue_track():
    data = request.get_json()
    if not data or 'uri' not in data:
        return jsonify({"error": "Missing track URI"}), 400

    access_token = get_access_token()
    if not access_token:
        return jsonify({"error": "Failed to authorize with Spotify"}), 500

    try:
        # Check active devices
        devices_response = session_retry.get(
            f"{API_BASE_URL}/me/player/devices",
            headers={'Authorization': f"Bearer {access_token}"},
            timeout=5
        )
        devices_data = devices_response.json()
        if not devices_data.get('devices'):
            return jsonify({
                "error": "No active devices",
                "solution": "Open Spotify on any device and start playback"
            }), 404

        # Queue the track
        queue_response = session_retry.post(
            f"{API_BASE_URL}/me/player/queue?uri={data['uri']}",
            headers={'Authorization': f"Bearer {access_token}"},
            timeout=5
        )
        if queue_response.status_code == 204:
            return jsonify({"success": True, "message": "Track added to queue"})
        else:
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
        return jsonify({"error": "Request timed out"}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Network error", "details": str(e)}), 503
    except Exception as e:
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)