# This script runs a Flask server responsible for hosting the main GoonSoft website.

# Import from flask
from flask import Flask, request, jsonify, render_template, flash, redirect, url_for, session, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_cors import CORS

# Import from other files
from models import db, User
from auth import role_required
from dbquery import query_steamstats_database

# Other dependencies
import requests
import os
import json
import datetime
import mysql.connector

from datetime import datetime
from dotenv import load_dotenv
from user_agents import parse as parse_ua
from werkzeug.security import generate_password_hash

# Load and define environment variables from .env file
load_dotenv()

DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
DISCORD_CHANNEL_ID = os.getenv("DISCORD_IPADDRESS_CHANNEL")
OUTSIDE_PORT = os.getenv("OUTSIDE_PORT")
ABSTRACT_API_KEY = os.getenv("ABSTRACT_API_KEY")
PATH_TO_WEBSITE = os.getenv("PATH_TO_WEBSITE")
SECRET_KEY = os.getenv("SECRET_KEY")
OLLAMA_API_URL = f"http://{str(os.getenv('OLLAMA_API_URL'))}/api/generate"

WEBAPP_VERSION = "3.0 Alpha"

# ---------- Flask initilization ----------

app = Flask(__name__)

CORS(app)

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}

# ---------- Authentication Stuff ----------

app.secret_key = SECRET_KEY

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for('register'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("User created successfully")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        print("Login Attempted!") #For debug
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('protected'))
        flash("Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
@role_required('admin')
def protected():
    session.pop("chat_history", None)  # Clear chat history on browser refresh
    return render_template('gateway.html', user=current_user, version=WEBAPP_VERSION)

# ---------- IP Logger ----------

def send_ip_to_discord(ip, data, user_agent_raw, method):
    '''
    This function collects and sends IP address data to a discord server, formatted as an embed.
    Takes IP, parsed JSON data, user agent information and request method as arguments. All should be strings.
    '''

    # Channel to send the IP message to
    url = f"https://discord.com/api/v10/channels/{DISCORD_CHANNEL_ID}/messages"
    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }

    current_time = datetime.now()

    # Parse user agent string
    ua = parse_ua(user_agent_raw or "")

    # Populate user agent information
    device_type = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "PC" if ua.is_pc else "Other"
    os_info = f"{ua.os.family} {ua.os.version_string}"
    browser_info = f"{ua.browser.family} {ua.browser.version_string}"

    # Setup the discord embed message as json
    embed = {
        "title": "New Visitor",
        "description": f"IP Address: `{ip}`",
        "color": 65280,  # Green
        "author": {
            "name": "Abstract IP Intelligence",
            "url": "https://www.abstractapi.com/",
            "icon_url": "https://cdn.prod.website-files.com/65166126ca18241731aa26b0/65390de624cb65770560dda5_FAV.png"
        },
        "fields": [
            {"name": "Approximate Location", "value": f"{data['location']['city']}, {data['location']['region']}, {data['location']['country']} {data['flag']['emoji']}", "inline": False},
            {"name": "Service Provider", "value": f"ISP: {data['company']['name']}\n"f"Domain: {data['company']['domain']}", "inline": False},
            {"name": "Request Method", "value": method, "inline": True},
            {"name": "Device Type", "value": device_type, "inline": True},
            {"name": "Operating System", "value": os_info, "inline": True},
            {"name": "Browser", "value": browser_info, "inline": True},
            {"name": "User Agent String", "value": user_agent_raw or "Unknown", "inline": False},
            {"name": "Timestamp", "value": current_time.strftime("%Y-%m-%d %H:%M:%S UTC"), "inline": False}
        ]
    }

    response_json_data = {"embeds": [embed]}

    response = requests.post(url, headers=headers, json=response_json_data)
    
    if response.status_code != 200 and response.status_code != 204:
        print("Failed to send message to Discord:", response.text)

# ---------- Main Flask Routes -----------

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

# IP revealer
@app.route("/reveal", methods=["POST"])
def reveal_ip():

    forwarded = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip = forwarded.split(",")[0].strip()
    user_agent = request.headers.get("User-Agent")
    method = request.method

    # Make a request to the Abstract API to get IP intelligence data and parse the response
    response = requests.get(f"https://ip-intelligence.abstractapi.com/v1/?api_key={ABSTRACT_API_KEY}&ip_address=" + ip)
    data = json.loads(response.text)

    send_ip_to_discord(ip, data, user_agent, method)

    #return response.json()  # Return the JSON response directly from the Abstract API for debugging if needed
    return jsonify({"ip": ip})

# ---------- Subroutes for iframes ----------

@app.route('/manage-users', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_users():
    # Handle role update or deletion
    if request.method == 'POST' and 'user_id' in request.form:
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        user = User.query.get(user_id)

        if user and str(user.id) != str(current_user.id):  # prevent self-action
            if action == 'promote':
                user.role = 'admin'
            elif action == 'demote':
                user.role = 'user'
            elif action == 'delete':
                db.session.delete(user)
            db.session.commit()
        return redirect(url_for('manage_users', q=request.args.get('q', ''), page=request.args.get('page', 1)))

    # Handle new user creation
    if request.method == 'POST' and 'new_username' in request.form:
        new_username = request.form['new_username']
        new_password = request.form['new_password']
        new_role = request.form.get('new_role', 'user')
        if new_username and new_password:
            if User.query.filter_by(username=new_username).first():
                flash('Username already exists.', 'error')
            else:
                hashed_pw = generate_password_hash(new_password)
                new_user = User(username=new_username, password=hashed_pw, role=new_role)
                db.session.add(new_user)
                db.session.commit()
                flash('User created successfully.', 'success')
        return redirect(url_for('manage_users'))

    # Filtering & Pagination
    query = User.query
    search_term = request.args.get('q', '')
    if search_term:
        query = query.filter(User.username.ilike(f'%{search_term}%'))

    page = int(request.args.get('page', 1))
    per_page = 5
    users = query.paginate(page=page, per_page=per_page)

    return render_template('manage_users.html', users=users, q=search_term)

@app.route("/chat", methods=["GET"])
@login_required
@role_required('admin')
def chat():
    return render_template("chat.html")

@app.route("/steamstats", methods=["GET"])
@login_required
@role_required('admin')
def steamstats():
    app_name = request.args.get('app', 'steamvr').lower()
    data = query_steamstats_database(app_name)
    gameName = data["name"]
    gameHours = data["hours"]
    gameDelta = data["delta"]

    return render_template("steamstats.html", name=gameName, hours=gameHours, delta=gameDelta)


@app.route("/botmanagement", methods=["GET"])
@login_required
@role_required('admin')
def botmanagement():
    return render_template("botmanagement.html")

@app.route("/appletsindex", methods=["GET"])
@login_required
@role_required('admin')
def appletsindex():
    return render_template("appletsindex.html")

# ---------- Subroutes for LLM ----------

'''
# Single generation mode

@app.route("/llmquery", methods=["POST"])
def llmquery():
    user_input = request.json.get("message")
    
    response = requests.post(OLLAMA_API_URL, json={
        "model": 'dolphin3:8b',
        "prompt": user_input,
        "stream": False
    })

    data = response.json()
    return jsonify({"response": data.get("response", "").strip()})
'''

@app.route("/llmquery", methods=["POST"])
@login_required
@role_required('admin')
def llmquery():
    user_input = request.json.get("message")
    if not user_input:
        return jsonify({"response": "No input received"}), 400

    # Retrieve chat history from session
    chat_history = session.get("chat_history", [])
    chat_history.append({"role": "user", "content": user_input})

    # Build prompt from history
    prompt = ""
    for msg in chat_history:
        role = "User" if msg["role"] == "user" else "Assistant"
        prompt += f"{role}: {msg['content']}\n"
    prompt += "Assistant:"

    # Send prompt to Ollama
    try:
        response = requests.post(OLLAMA_API_URL, json={
            "model": 'dolphin3:8b',
            "prompt": prompt,
            "stream": False
        })

        data = response.json()
        bot_response = data.get("response", "").strip()

        # Update session history
        chat_history.append({"role": "assistant", "content": bot_response})
        session["chat_history"] = chat_history

        return jsonify({"response": bot_response})

    except Exception as e:
        return jsonify({"response": f"Error: {str(e)}"}), 500

@app.route('/reset', methods=['POST'])
@login_required
@role_required('admin')
def reset():
    session.pop("chat_history", None)
    return jsonify({"status": "cleared"})

# ---------- Run the app ----------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=OUTSIDE_PORT, debug=True)