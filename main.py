from flask import Flask, render_template, jsonify, send_file, request, redirect, url_for, session, flash, make_response
import docker
import socket
import json
import re
import psutil
import os
import hashlib
import logging
from functools import wraps
from pathlib import Path
import secrets
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Generate a secure random key for sessions
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))

# Base URL for GitHub-hosted icons
GITHUB_ICON_BASE_URL = "https://raw.githubusercontent.com/JesseHoekema/simple-icons/refs/heads/develop/icons/"

# Constants
SETTINGS_FILE = 'settings.json'
ICON_MAPPING_FILE = 'icon_mapping.json'
DEFAULT_BACKGROUND = "/background-1"

# Ensure necessary directories exist
Path('static').mkdir(exist_ok=True)
Path('templates').mkdir(exist_ok=True)

@app.after_request
def add_no_cache_headers(response):
    """
    Add headers to disable caching for all responses.
    """
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


def login_required(f):
    """Decorator to require login for specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_host_ip():
    """Fetch the real IP address of the host machine."""
    try:
        # Create a temporary socket to find the default route
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect to a public DNS server (e.g., Google's 8.8.8.8)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
        return ip_address
    except Exception as e:
        logger.error(f"Error fetching host IP: {e}")
        return "127.0.0.1"  # Fallback to localhost if unable to fetch

def load_settings():
    """Load settings from a JSON file, creating it if it doesn't exist."""
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as file:
                return json.load(file)
        else:
            default_settings = {"firstsetup": True, "background_url": DEFAULT_BACKGROUND}
            save_settings(default_settings)
            return default_settings
    except json.JSONDecodeError:
        logger.error("Settings file is corrupted. Resetting to default.")
        return {"firstsetup": True, "background_url": DEFAULT_BACKGROUND}
    except Exception as e:
        logger.error(f"Error loading settings: {e}")
        return {"firstsetup": True, "background_url": DEFAULT_BACKGROUND}

def save_settings(settings):
    """Save settings to the JSON file."""
    try:
        with open(SETTINGS_FILE, "w") as file:
            json.dump(settings, file, indent=4)
        return True
    except PermissionError:
        logger.error("Permission denied while saving settings.")
        return False
    except Exception as e:
        logger.error(f"Error saving settings: {e}")
        return False

def load_icon_mapping():
    """Load the icon mapping from a JSON file."""
    try:
        if os.path.exists(ICON_MAPPING_FILE):
            with open(ICON_MAPPING_FILE, "r") as file:
                return json.load(file)
        else:
            # Create a default icon mapping
            default_mapping = {
                "nginx": "nginx.svg",
                "apache": "apache.svg",
                "mysql": "mysql.svg",
                "postgres": "postgresql.svg",
                "mongo": "mongodb.svg",
                "redis": "redis.svg",
                "node": "nodedotjs.svg",
                "php": "php.svg",
                "python": "python.svg"
            }
            with open(ICON_MAPPING_FILE, "w") as file:
                json.dump(default_mapping, file, indent=4)
            return default_mapping
    except Exception as e:
        logger.error(f"Error loading icon mapping: {e}")
        return {}

def get_docker_client():
    """Get a Docker client with error handling."""
    try:
        client = docker.DockerClient(base_url="unix:///var/run/docker.sock")
        client.ping()
        return client
    except Exception as unix_error:
        logger.warning(f"Failed to connect via Unix socket: {unix_error}")

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    """Verify a password against a stored hash."""
    return stored_hash == hash_password(password)

ICON_MAPPING = load_icon_mapping()

def get_app_icon(container_name, container_image):
    """
    Map container names/images to GitHub-hosted app icons.
    Returns the URL of the icon or a default placeholder.
    """
    # Normalize container name and image by splitting into words
    def normalize(name_or_image):
        if not name_or_image:
            return []
        # Split by common delimiters (e.g., -, _, .)
        parts = re.split(r'[-_\.]', name_or_image.lower())
        return [p for p in parts if p]  # Filter out empty strings

    # Normalize container name and image
    container_name_parts = normalize(container_name)
    container_image_parts = normalize(container_image)

    # Check if the container name or image matches any key in the mapping
    for key in ICON_MAPPING:
        # Match whole words only
        if key in container_name_parts or key in container_image_parts:
            return f"{GITHUB_ICON_BASE_URL}/{ICON_MAPPING[key]}"
    
    # Default placeholder icon
    return f"{GITHUB_ICON_BASE_URL}/docker.svg"

def get_system_stats():
    """
    Fetch real-time system statistics (CPU, RAM).
    """
    try:
        cpu_usage = psutil.cpu_percent(interval=0.5)  # CPU usage as a percentage
        ram = psutil.virtual_memory()
        ram_usage = ram.percent  # RAM usage as a percentage
        ram_total = ram.total / (1024 * 1024 * 1024)  # Total RAM in GB
        ram_used = ram.used / (1024 * 1024 * 1024)  # Used RAM in GB
        
        return {
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "ram_total": f"{ram_total:.2f} GB",
            "ram_used": f"{ram_used:.2f} GB"
        }
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return {
            "cpu_usage": 0,
            "ram_usage": 0,
            "ram_total": "0 GB",
            "ram_used": "0 GB",
            "error": str(e)
        }

@app.route('/')
@login_required
def index():
    # Connect to the Docker daemon
    client = docker.DockerClient(base_url="unix:///var/run/docker.sock")
    
    # Fetch all containers (both running and stopped)
    containers = client.containers.list(all=True)
    
    # Fetch the host IP address
    host_ip = get_host_ip()
    
    # Prepare container info for rendering
    container_info = []
    for container in containers:
        # Extract port mappings
        ports = container.attrs['NetworkSettings']['Ports']
        
        # Initialize URL as None by default
        url = None
        
        # Check if the container has exposed ports
        if ports:
            for container_port, host_bindings in ports.items():
                if host_bindings:
                    for binding in host_bindings:
                        host_port = binding['HostPort']
                        # Construct the URL for the web interface
                        url = f"http://{host_ip}:{host_port}"
                        break  # Use the first valid binding
        
        # Get the app icon
        container_image = container.image.tags[0] if container.image.tags else "No tag"
        icon_url = get_app_icon(container.name, container_image)
        
        # Add container info
        container_data = {
            "id": container.short_id,
            "name": container.name,
            "image": container_image,
            "status": container.status,  # Running or Exited
            "url": url,  # Will be None if no exposed ports
            "icon": icon_url
        }
        container_info.append(container_data)
    
    # Sort containers: running first, then stopped
    container_info.sort(key=lambda x: x["status"] != "running")
    
    system_stats = get_system_stats()
    
    # Pass the sorted container info to the HTML template
    return render_template('index.html', containers=container_info, system_stats=system_stats)

@app.route('/setup')
def setup():
    """Setup page for first-time configuration."""
    settings = load_settings()
    if not settings.get('firstsetup', True):
        return redirect(url_for('index'))
    return render_template('setup.html')

@app.route('/api/system/stats', methods=['GET'])
@login_required
def api_system_stats():
    """API endpoint to get system statistics."""
    data = get_system_stats()
    return jsonify(data)

@app.route('/background-1')
def get_image():
    """Serve the first background image."""
    try:
        return send_file('static/signin.png', mimetype='image/png')
    except FileNotFoundError:
        return send_file('signin.png', mimetype='image/png')

@app.route('/background-2')
def get_bg2():
    """Serve the second background image."""
    try:
        return send_file('static/signup.png', mimetype='image/png')
    except FileNotFoundError:
        return send_file('signup.png', mimetype='image/png')

@app.route('/astronaut')
def get_astronaut():
    """Serve the astronaut image."""
    try:
        return send_file('static/astronout.png', mimetype='image/png')
    except FileNotFoundError:
        return send_file('astronout.png', mimetype='image/png')

@app.route('/bg-icon')
def get_bg_icon():
    """Serve the background icon image."""
    try:
        return send_file('static/bg-icon.png', mimetype='image/png')
    except FileNotFoundError:
        return send_file('bg-icon.png', mimetype='image/png')

@app.route('/api/system/register', methods=['POST'])
def register():
    """API endpoint to register a new user."""
    data = request.get_json()

    # Check if username and password are in the data
    if 'username' in data and 'password' in data:
        try:
            settings = load_settings()
            
            # Hash the password for security
            settings['username'] = data['username']
            settings['password_hash'] = hash_password(data['password'])
            settings['firstsetup'] = False
            
            if save_settings(settings):
                return jsonify({"message": "User registered successfully"}), 200
            else:
                return jsonify({"error": "Failed to save settings"}), 500
        except Exception as e:
            logger.error(f"Error in registration: {e}")
            return jsonify({"error": f"Registration error: {str(e)}"}), 500
    else:
        return jsonify({"error": "Username and password required"}), 400

@app.route('/api/settings/background')
def get_bgsettings():
    """API endpoint to get the current background setting."""
    settings = load_settings()
    background = settings.get("background_url", DEFAULT_BACKGROUND)
    return jsonify({"background": background})

def is_valid_url(url):
    """Validate if the given string is a valid URL or a special path."""
    # Check for special paths first
    if url in ['/background-1', '/background-2', 'background-1', 'background-2']:
        return True
    
    # Otherwise validate as a normal URL
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

@app.route('/api/settings/background/set', methods=['POST'])
def set_background():
    """API endpoint to set the background image."""
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Invalid JSON body. Ensure the body contains a "url" field.'}), 400

    background_url = data.get('url')

    # Validate the URL
    if not is_valid_url(background_url):
        return jsonify({'error': 'Invalid URL provided.'}), 400

    # Update the settings
    settings = load_settings()
    settings['background_url'] = background_url

    if save_settings(settings):
        return jsonify({'message': 'Background set successfully', 'background_url': background_url}), 200
    else:
        return jsonify({'error': 'Failed to save settings'}), 500

@app.route('/api/settings/firstsetup', methods=['GET', 'POST'])
def get_firstsetup():
    """API endpoint to get or set the first setup status."""
    settings = load_settings()
    
    if request.method == 'GET':
        # Check if 'firstsetup' exists, if not, return true
        firstsetup = settings.get("firstsetup", True)
        return jsonify({"firstsetup": firstsetup})
    
    elif request.method == 'POST':
        # Update the 'firstsetup' status based on the request body
        data = request.get_json()
        status = data.get("status")
        if status is not None:
            settings["firstsetup"] = status
            if save_settings(settings):
                return jsonify({"message": "firstsetup updated successfully", "firstsetup": status})
            else:
                return jsonify({"error": "Failed to save settings"}), 500
        else:
            return jsonify({"error": "Status value is required"}), 400

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication handler."""
    settings = load_settings()
    
    # If first setup is still needed, redirect to setup
    if settings.get('firstsetup', True):
        return redirect(url_for('setup'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html')

        # Check credentials
        stored_username = settings.get('username')
        stored_hash = settings.get('password_hash')
        
        # For backward compatibility with old plain-text passwords
        if 'password' in settings and not stored_hash:
            if settings.get('password') == password:
                settings['password_hash'] = hash_password(password)
                settings.pop('password', None)
                save_settings(settings)
                session['username'] = username
                return redirect(url_for('index'))
            else:
                flash('Invalid credentials')
                return render_template('login.html')
        elif not stored_hash:
            flash('Password not set. Please contact the administrator.')
            return render_template('login.html')
        
        # Normal password verification
        if stored_username == username and stored_hash and verify_password(stored_hash, password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout handler."""
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/settings')
@login_required
def open_settings():
    """Settings page."""
    return render_template('settings.html')

@app.route('/settings/account')
@login_required
def open_settings_account():
    """Account settings page."""
    return render_template('settings/account.html')

@app.route('/settings/background')
@login_required
def open_settings_background():
    """Account settings page."""
    return render_template('settings/background.html')

@app.route('/settings/delete')
@login_required
def open_settings_delete():
    """Account settings page."""
    return render_template('settings/delete.html')



@app.route('/api/container/action', methods=['POST'])
@login_required
def container_action():
    """API endpoint to perform actions on containers."""
    data = request.get_json()
    if not data or 'container_id' not in data or 'action' not in data:
        return jsonify({"error": "Container ID and action required"}), 400
    
    container_id = data.get('container_id')
    action = data.get('action')
    
    client = get_docker_client()
    if not client:
        return jsonify({"error": "Could not connect to Docker"}), 500
    
    try:
        container = client.containers.get(container_id)
        
        if action == "start":
            container.start()
            return jsonify({"message": f"Container {container.name} started"})
        elif action == "stop":
            container.stop()
            return jsonify({"message": f"Container {container.name} stopped"})
        elif action == "restart":
            container.restart()
            return jsonify({"message": f"Container {container.name} restarted"})
        else:
            return jsonify({"error": "Invalid action"}), 400
    except Exception as e:
        logger.error(f"Error performing container action: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    """API endpoint to change user password."""
    data = request.get_json()
    if not data or 'current_password' not in data or 'new_password' not in data:
        return jsonify({"error": "Current and new password required"}), 400
    
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    settings = load_settings()
    
    # Check current password
    stored_hash = settings.get('password_hash')
    if not stored_hash:
        # For backward compatibility
        if settings.get('password') != current_password:
            return jsonify({"error": "Current password is incorrect"}), 401
    elif not verify_password(stored_hash, current_password):
        return jsonify({"error": "Current password is incorrect"}), 401
    
    # Update password
    settings['password_hash'] = hash_password(new_password)
    settings.pop('password', None)  # Remove old plain-text password if it exists
    
    if save_settings(settings):
        return jsonify({"message": "Password changed successfully"})
    else:
        return jsonify({"error": "Failed to save settings"}), 500

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    """Delete the user account."""
    password = request.form.get('password')

    if not password:
        return jsonify({"error": "Password is required"}), 400

    try:
        settings = load_settings()
        stored_hash = settings.get('password_hash')

        if not stored_hash:
            return jsonify({"error": "No password hash found in settings"}), 500

        if not verify_password(stored_hash, password):
            return jsonify({"error": "Incorrect password"}), 401

        # Clear settings and logout user
        with open(SETTINGS_FILE, 'w') as f:
            json.dump({}, f, indent=4)
        session.clear()  # Clear the session

        return jsonify({"message": "Account deleted successfully"}), 200
    except FileNotFoundError:
        return jsonify({"error": "Settings file not found"}), 404
    except Exception as e:
        logger.error(f"Error deleting account: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('error.html', message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return render_template('error.html', message="Server error: " + str(e)), 500

# Create a basic error.html template if it doesn't exist
def create_error_template():
    """Create a basic error template if it doesn't exist."""
    error_template_path = os.path.join('templates', 'error.html')
    if not os.path.exists(error_template_path):
        error_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background-color: #f5f5f5;
                }
                .error-container {
                    background-color: white;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                    text-align: center;
                }
                h1 {
                    color: #e74c3c;
                }
                .button {
                    display: inline-block;
                    background-color: #3498db;
                    color: white;
                    padding: 10px 20px;
                    border-radius: 5px;
                    text-decoration: none;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="error-container">
                <h1>Error</h1>
                <p>{{ message }}</p>
                <a href="{{ url_for('index') }}" class="button">Go to Dashboard</a>
            </div>
        </body>
        </html>
        """
        with open(error_template_path, 'w') as f:
            f.write(error_template)


@app.route('/None')
def none():
    """Handle requests to /None."""
    return render_template('none.html')
if __name__ == '__main__':
    # Create basic templates if they don't exist
    create_error_template()
    # Set debug mode based on environment
    # For security, bind to localhost only in debug mode
    host = '0.0.0.0'
    port = int(os.environ.get('PORT', 5010))
    app.run(debug=True, host=host, port=port)
