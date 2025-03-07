import discord
from discord.ext import commands
import requests
import base64
import re
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve environment variables
VT_API_KEY = os.getenv("VT_API_KEY")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
REPORTS_CHANNEL_ID = int(os.getenv("REPORTS_CHANNEL_ID"))

# Set up intents
intents = discord.Intents.default()  # Includes guilds, which is needed for channel access
intents.message_content = True       

# Initialize the bot with the prefix and intents
bot = commands.Bot(command_prefix='/', intents=intents)

@bot.event
async def on_ready():
    print(f'{bot.user}? IT\'S ALIVE!')

def get_vt_report(url):
    """Gets the report from VirusTotal, I don’t even know how this works :sob:"""
    url_bytes = url.encode('ascii')
    base64_bytes = base64.urlsafe_b64encode(url_bytes)
    base64_url = base64_bytes.decode('ascii').rstrip('=')
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{base64_url}", headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None
    else:
        response.raise_for_status()

@bot.command()
async def report(ctx, *, args):
    """
    Reports scam links to a designated channel.
    
    Format: /report url: <url> provider: <provider> reason: <reason>
    Example: /report url: probablynotgoogle.com provider: cloudfare reason: Phishing
    """
    url_match = re.search(r'url:\s*(\S+)', args)
    provider_match = re.search(r'provider:\s*(\S+)', args)
    reason_match = re.search(r'reason:\s*(.+)', args)
    
    if url_match and provider_match and reason_match:
        url = url_match.group(1)
        provider = provider_match.group(1)
        reason = reason_match.group(1).strip()
    else:
        await ctx.send("Invalid format. Use: `/report url: <url> provider: <provider> reason: <reason>`")
        return
    
    reports_channel = bot.get_channel(REPORTS_CHANNEL_ID)
    if reports_channel is None:
        await ctx.send("Reports channel not found. Please contact the administrator.")
        return
    
    report_message = f"New report:\n**URL**: {url}\n**Provider**: {provider}\n**Reason**: {reason}"
    await reports_channel.send(report_message)
    await ctx.send("Report submitted successfully.")

@bot.command()
async def check(ctx, *, url: str):
    """
    Checks a link using VirusTotal's API.
    Format: /check <url>
    Example: /check http://example.com
    """
    url = url.strip()
    try:
        report = get_vt_report(url)
        if report is None:
            await ctx.send(f"No scan report available for `{url}` in VirusTotal's database.")
        else:
            stats = report['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            total = malicious + suspicious + harmless + undetected
            
            message = f"**VirusTotal Scan Results for `{url}`**:\n"
            message += f"Scanned by {total} engines:\n"
            message += f"- Malicious: {malicious}\n"
            message += f"- Suspicious: {suspicious}\n"
            message += f"- Harmless: {harmless}\n"
            message += f"- Undetected: {undetected}\n"
            
            if malicious > 0:
                results = report['data']['attributes']['last_analysis_results']
                malicious_engines = [
                    engine for engine, result in results.items()
                    if result['category'] == 'malicious'
                ]
                message += "**Detected as malicious by**: " + ', '.join(malicious_engines)
            
            await ctx.send(message)
    except requests.RequestException as e:
        await ctx.send(f"Error accessing VirusTotal API: {str(e)}")

# Run the bot
bot.run(DISCORD_BOT_TOKEN)