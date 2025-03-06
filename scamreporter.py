import discord
from discord.ext import commands
import requests
import base64
import re
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve API keys and tokens from environment variables
VT_API_KEY = os.getenv("VT_API_KEY")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
REPORTS_CHANNEL_ID = int(os.getenv("REPORTS_CHANNEL_ID"))

bot = commands.Bot(command_prefix='/')

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')

def get_vt_report(url):
    """Encodes the URL and retrieves its scan report from VirusTotal."""
    url_bytes = url.encode('ascii')
    base64_bytes = base64.urlsafe_b64encode(url_bytes)
    base64_url = base64_bytes.decode('ascii').rstrip('=')
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{base64_url}", headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None  # URL not in VirusTotal database
    else:
        response.raise_for_status()  # Raise exception for other errors

# Run the bot
bot.run(DISCORD_BOT_TOKEN)
