import discord
from discord.ext import commands
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up intents
intents = discord.Intents.default()
intents.message_content = True  # Required for reading message content

# Initialize the bot
bot = commands.Bot(command_prefix="/", intents=intents)

@bot.event
async def on_ready():
    print(f"Bot is online as {bot.user}")

# Function: Get VirusTotal report for a URL
async def get_virustotal_report(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    params = {'apikey': api_key, 'resource': url, 'scan': 1}
    async with aiohttp.ClientSession() as session:
        # Initial request to get report or submit for scanning
        async with session.get("https://www.virustotal.com/vtapi/v2/url/report", params=params) as response:
            data = await response.json()
            if data['response_code'] == 1:
                return data
            elif data['response_code'] == 0:
                # URL submitted for scanning; poll until report is ready
                for _ in range(5):
                    await asyncio.sleep(15)
                    async with session.get("https://www.virustotal.com/vtapi/v2/url/report", params={'apikey': api_key, 'resource': url}) as retry_response:
                        retry_data = await retry_response.json()
                        if retry_data['response_code'] == 1:
                            return retry_data
                return {"error": "Scan took too long, please try again later."}
            else:
                return {"error": "Error in VirusTotal API response."}

# Command: /report url:<url> provider:<provider> reason:<reason>
@bot.command()
async def report(ctx, *, args: str):
    args_list = args.split()
    try:
        # Find indices of labels
        url_index = args_list.index("url:")
        provider_index = args_list.index("provider:")
        reason_index = args_list.index("reason:")
        # Ensure labels are in correct order and have values
        if url_index >= provider_index or provider_index >= reason_index:
            raise ValueError
        url = " ".join(args_list[url_index + 1:provider_index])
        provider = " ".join(args_list[provider_index + 1:reason_index])
        reason = " ".join(args_list[reason_index + 1:])
        if not url or not provider or not reason:
            raise ValueError
    except ValueError:
        await ctx.send("Invalid format. Please use /report url:<url> provider:<provider> reason:<reason>")
        return

    # Get report channel and send report
    report_channel_id = int(os.getenv("REPORT_CHANNEL_ID"))
    report_channel = bot.get_channel(report_channel_id)
    if report_channel is None:
        await ctx.send("Report channel not found. Please check the configuration.")
        return
    await report_channel.send(f"New report:\nURL: {url}\nProvider: {provider}\nReason: {reason}\nReported by: {ctx.author.mention}")
    await ctx.send("Your report has been logged.")

# Command: /check <url>
@bot.command()
async def check(ctx, url: str):
    # Basic URL validation
    if not url.startswith("http://") and not url.startswith("https://"):
        await ctx.send("Please provide a valid URL starting with http:// or https://")
        return
    
    await ctx.send("Checking URL with VirusTotal, please wait...")
    report = await get_virustotal_report(url)
    
    # Handle report results or errors
    if "error" in report:
        await ctx.send(report["error"])
    else:
        positives = report["positives"]
        total = report["total"]
        if positives > 0:
            await ctx.send(f"The URL is detected as malicious by {positives} out of {total} engines.")
        else:
            await ctx.send(f"The URL is clean according to {total} engines.")

# Run the bot with the Discord token
bot.run(os.getenv("DISCORD_TOKEN"))