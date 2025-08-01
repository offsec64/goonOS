# This script runs a Flask server responsible for hosting the main GoonSoft website.
# 

from flask import Flask, request, jsonify, render_template, flash, redirect, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User
import requests
import os
import json
import datetime
from datetime import datetime
from dotenv import load_dotenv
from user_agents import parse as parse_ua

# Load environment variables from .env file
load_dotenv()
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
DISCORD_CHANNEL_ID = os.getenv("DISCORD_IPADDRESS_CHANNEL")
OUTSIDE_PORT = os.getenv("OUTSIDE_PORT")
ABSTRACT_API_KEY = os.getenv("ABSTRACT_API_KEY")
PATH_TO_WEBSITE = os.getenv("PATH_TO_WEBSITE")

WEBAPP_VERSION = "1.3 ALPHA"

app = Flask(__name__)

# ---------- Authentication Stuff ----------

app.secret_key = os.urandom(24)  # Use a secure secret key!
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
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('protected'))
        flash("Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/protected')
@login_required
def protected():
    return render_template('protected.html', user=current_user)


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

@app.route("/dashboard", methods=["GET"])
def gateway():
    return render_template("gateway.html", version=WEBAPP_VERSION) # Send webapp version to be insterted into document with jinja

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

@app.route("/chat", methods=["GET"])
def chat():
    return render_template("chat.html")

@app.route("/steamstats", methods=["GET"])
def steamstats():
    return render_template("steamstats.html")

@app.route("/botmanagement", methods=["GET"])
def botmanagement():
    return render_template("botmanagement.html")

@app.route("/appletsindex", methods=["GET"])
def appletsindex():
    return render_template("appletsindex.html")

# ---------- Run the app ----------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=OUTSIDE_PORT)