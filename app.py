import warnings
from urllib3.exceptions import NotOpenSSLWarning
warnings.filterwarnings("ignore", category=NotOpenSSLWarning)

import os
import re
import base64
import logging
from flask import Flask, render_template, request, jsonify, abort
import requests
from urllib.parse import urlencode
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY').encode()

# Spotify credentials
CLIENT_ID = '4781e6fbedae431dbbc4c586fcce9d06'
CLIENT_SECRET = '09fcf15964624fc4a616abf76f2c4371'
REFRESH_TOKEN = 'AQAC0LbZpQo6A78s5D5PMTjvbMRqwsiVaIshd8VXkKEioa6emtoJfhukyFH1d1yK08hYyyAXypIkErZ_FX9tkIvL68gHoyHeE7TfLfzGTujhsyWvzkJ22WuQ600bo7CNIGU'

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

# Restrict access to local network
ALLOWED_PUBLIC_IPS = ['109.177.122.196'] # Change this if your router uses another subnet

@app.before_request
def restrict_to_public_ip():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    logger.info(f"Request from IP: {ip}")
    
def restrict_to_public_ip():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    logger.info(f"Incoming request from IP: {ip}")
    if ip not in ALLOWED_PUBLIC_IPS:
        abort(403, description="Access restricted to café Wi-Fi only.")

# Allow only Arabic or English songs
def is_arabic_or_english(text):
    arabic_re = re.compile(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]')
    latin_re = re.compile(r'[a-zA-Z]')
    has_arabic = bool(arabic_re.search(text))
    has_latin = bool(latin_re.search(text))
    return has_arabic or has_latin

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
        return response.json()['access_token']
    except Exception as e:
        logger.error(f"Access token retrieval failed: {str(e)}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

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

        filtered_tracks = []
        for track in tracks:
            title = track["name"]
            artist = track["artists"][0]["name"]
            if is_arabic_or_english(f"{title} {artist}"):
                filtered_tracks.append({
                    "name": title,
                    "artist": artist,
                    "uri": track["uri"],
                    "image": track["album"]["images"][0]["url"] if track["album"]["images"] else None
                })

        return jsonify(filtered_tracks)
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return jsonify({"error": str(e)}), 500
@app.route('/queue-spotify')
def get_spotify_queue():
    access_token = get_access_token()
    if not access_token:
        return jsonify({"error": "Failed to authorize with Spotify"}), 500

    try:
        response = session_retry.get(
            f"{API_BASE_URL}/me/player/queue",
            headers={'Authorization': f"Bearer {access_token}"}
        )

        if response.status_code == 204:
            return jsonify({"message": "No active device or queue available"}), 204

        response.raise_for_status()
        queue_data = response.json()

        formatted_response = {
            "currently_playing": None,
            "queue": []
        }

        if queue_data.get('currently_playing'):
            track = queue_data['currently_playing']
            formatted_response["currently_playing"] = {
                "name": track['name'],
                "artist": track['artists'][0]['name'],
                "image": track['album']['images'][0]['url'] if track['album']['images'] else None,
                "uri": track['uri'],
                "duration_ms": track['duration_ms'],
                "id": track['id']
            }

        if queue_data.get('queue'):
            formatted_response["queue"] = [
                {
                    "name": item['name'],
                    "artist": item['artists'][0]['name'],
                    "image": item['album']['images'][0]['url'] if item['album']['images'] else None,
                    "uri": item['uri'],
                    "duration_ms": item['duration_ms'],
                    "id": item['id']
                } for item in queue_data['queue']
            ]

        return jsonify(formatted_response)

    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error getting queue: {http_err}")
        return jsonify({"error": "Failed to get queue", "details": str(http_err)}), 500
    except Exception as e:
        logger.error(f"Queue retrieval error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/queue', methods=['POST'])
def queue_track():
    data = request.get_json()
    if not data or 'uri' not in data:
        return jsonify({"error": "Missing track URI"}), 400

    access_token = get_access_token()
    if not access_token:
        return jsonify({"error": "Failed to authorize with Spotify"}), 500

    try:
        track_id = data['uri'].split(':')[-1]
        track_info_response = session_retry.get(
            f"{API_BASE_URL}/tracks/{track_id}",
            headers={'Authorization': f"Bearer {access_token}"}
        )
        track_info = track_info_response.json()
        title = track_info.get("name", "")
        artist = track_info["artists"][0]["name"]
        if not is_arabic_or_english(f"{title} {artist}"):
            return jsonify({"error": "Only English or Arabic songs are allowed."}), 403

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
