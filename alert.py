```python
import discord
from discord.ext import commands
import asyncio
import re
import aiohttp
import datetime
import pytz
import logging
import os
import json
import subprocess
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from io import BytesIO

# Configuration
MESSAGE_ID_FILE = "/var/log/discord_message_id.json"
OPENVPN_STATUS_PATHS = [
    "/etc/openvpn/server/status.log",
    "/run/openvpn-server/status-server.log",
    "/var/log/openvpn-status.log",
    "/var/log/openvpn.log",
    "/run/openvpn/status.log",
    "/etc/openvpn/status.log"
]
REFRESH_INTERVAL = 60
ACTIVE_CLIENT_THRESHOLD = 120  # Reduced to 2 minutes for stricter tracking
MAX_HISTORY_POINTS = 60
STATUS_LOG_MAX_AGE = 300

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    filename='/var/log/vpn_monitor.log',
    format="%(asctime)s %(levelname)s: %(message)s"
)

# Global variables
prev_inbound = 0
prev_outbound = 0
prev_rx_packets = 0
prev_tx_packets = 0
prev_time = None
history = []

def get_system_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.readline().split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            return f"{days}d {hours}h {minutes}m"
    except Exception as e:
        logging.warning(f"Failed to get system uptime: {e}")
        return "Unknown"

def check_openvpn_service():
    try:
        output = subprocess.check_output(["systemctl", "is-active", "openvpn@server"], stderr=subprocess.STDOUT).decode().strip()
        if output == "active":
            return "openvpn@server"
    except subprocess.CalledProcessError:
        pass
    try:
        output = subprocess.check_output(["systemctl", "is-active", "openvpn-server@server"], stderr=subprocess.STDOUT).decode().strip()
        if output == "active":
            return "openvpn-server@server"
    except subprocess.CalledProcessError:
        pass
    try:
        output = subprocess.check_output(["systemctl", "is-active", "openvpn"], stderr=subprocess.STDOUT).decode().strip()
        if output == "active":
            return "openvpn"
    except subprocess.CalledProcessError:
        pass
    try:
        subprocess.check_output(["pgrep", "openvpn"], stderr=subprocess.STDOUT)
        return "manual_openvpn"
    except subprocess.CalledProcessError:
        return None

def get_user_config():
    vpn_type = input("Is this OpenVPN or WireGuard? ").strip().lower()
    if vpn_type not in ['openvpn', 'wireguard']:
        print("Invalid input, must be 'openvpn' or 'wireguard'. Exiting.")
        sys.exit(1)
    
    network_adapter = input(f"What is the network adapter? (default: {'tun0' if vpn_type == 'openvpn' else 'wg0'}) ").strip()
    if not network_adapter:
        network_adapter = 'tun0' if vpn_type == 'openvpn' else 'wg0'
    
    server_location = input("What location is this server? ").strip()
    
    protocol = input("Is it UDP or TCP? ").strip().upper()
    if protocol not in ['UDP', 'TCP']:
        print("Invalid input, must be 'UDP' or 'TCP'. Defaulting to UDP.")
        protocol = 'UDP'

    bot_token = input("Enter your Discord Bot Token: ").strip()
    try:
        channel_id = int(input("Enter the Discord Channel ID to post updates: ").strip())
    except ValueError:
        print("Invalid channel ID, must be an integer. Exiting.")
        sys.exit(1)
    
    return {
        "vpn_type": vpn_type.capitalize(),
        "network_adapter": network_adapter,
        "server_location": server_location,
        "protocol": protocol,
        "bot_token": bot_token,
        "channel_id": channel_id
    }

async def get_openvpn_info(config):
    try:
        status_log = None
        for path in OPENVPN_STATUS_PATHS:
            if os.path.exists(path) and os.access(path, os.R_OK):
                status_log = path
                break
        if not status_log:
            logging.error("No readable OpenVPN status log found in common paths")
            return None

        try:
            log_mtime = os.path.getmtime(status_log)
            current_time = datetime.datetime.now().timestamp()
            if current_time - log_mtime > STATUS_LOG_MAX_AGE:
                logging.warning(f"OpenVPN status log {status_log} is outdated (last modified {int(current_time - log_mtime)}s ago)")
                return None
        except Exception as e:
            logging.warning(f"Failed to check status log mtime: {e}")

        inbound_bytes = 0
        outbound_bytes = 0
        active_ips = set()
        current_time = datetime.datetime.now().timestamp()

        try:
            with open(status_log, "r") as f:
                status_output = f.read()
            if not status_output.strip():
                logging.error(f"OpenVPN status log {status_log} is empty")
                return None
            logging.debug(f"OpenVPN status log content:\n{status_output}")
        except Exception as e:
            logging.error(f"Failed to read OpenVPN status log at {status_log}: {e}")
            return None

        lines = status_output.splitlines()
        for line in lines:
            line = line.strip()
            if line.startswith("CLIENT_LIST"):
                parts = line.split(",")
                if len(parts) >= 8:
                    real_address = parts[1]  # IP:port
                    ip_only = real_address.split(":")[0]  # Extract IP without port
                    try:
                        connected_since = float(parts[4])  # Unix timestamp
                        # Only count IPs connected within ACTIVE_CLIENT_THRESHOLD
                        if current_time - connected_since <= ACTIVE_CLIENT_THRESHOLD:
                            active_ips.add(ip_only)
                            rx_bytes = int(parts[5])
                            tx_bytes = int(parts[6])
                            inbound_bytes += rx_bytes
                            outbound_bytes += tx_bytes
                    except (ValueError, IndexError):
                        logging.warning(f"Invalid timestamp or data in CLIENT_LIST: {line}")
                        continue

        active_clients = len(active_ips)
        logging.info(f"OpenVPN: {active_clients} live connected IPs: {', '.join(active_ips)}")

        return {
            "connection_type": config["vpn_type"],
            "active_clients": active_clients,
            "inbound_bytes": inbound_bytes,
            "outbound_bytes": outbound_bytes,
            "protocol": config["protocol"],
            "status_log": status_log
        }
    except Exception as e:
        logging.error(f"Exception in get_openvpn_info: {e}")
        return None

async def get_wireguard_info(config):
    try:
        wg_interface = config["network_adapter"]
        try:
            wg_output = subprocess.check_output(["wg", "show", wg_interface], stderr=subprocess.STDOUT).decode()
            logging.debug(f"WireGuard raw output for {wg_interface}:\n{wg_output}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to run 'wg show {wg_interface}': {e.output.decode()}")
            return None

        active_ips = set()
        inbound_bytes = 0
        outbound_bytes = 0
        peer_data = []
        current_peer = {}
        peer_id = 0

        lines = wg_output.splitlines()
        for line in lines + [""]:
            if line.startswith("peer:"):
                if current_peer:
                    peer_data.append(current_peer)
                peer_id += 1
                current_peer = {"peer_id": peer_id, "handshake": None, "rx": 0, "tx": 0, "endpoint": None}
            elif "latest handshake" in line:
                m = re.search(r"latest handshake:\s+(\d+)\s+(second|minute)s?", line)
                if m:
                    value, unit = m.groups()
                    seconds = int(value) * (60 if unit == "minute" else 1)
                    current_peer["handshake"] = seconds
            elif "transfer:" in line:
                m = re.search(r'transfer:\s*([\d.]+)\s*(\w+) received,\s*([\d.]+)\s*(\w+) sent', line)
                if m:
                    rx_val, rx_unit, tx_val, tx_unit = m.groups()
                    def to_bytes(val, unit):
                        val = float(val)
                        units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
                        return int(val * units.get(unit, 1))
                    current_peer["rx"] = to_bytes(rx_val, rx_unit)
                    current_peer["tx"] = to_bytes(tx_val, tx_unit)
            elif line.startswith("endpoint:"):
                endpoint = line.split(":", 1)[1].strip()
                current_peer["endpoint"] = endpoint
        if current_peer:
            peer_data.append(current_peer)

        logging.debug(f"Parsed WireGuard peers: {json.dumps(peer_data, indent=2)}")

        for peer in peer_data:
            logging.debug(f"Peer {peer['peer_id']}: handshake={peer['handshake']}, endpoint={peer['endpoint']}, rx={peer['rx']}, tx={peer['tx']}")
            # Only count peers with recent handshake and valid endpoint
            if (peer.get("handshake") is not None and peer.get("handshake") <= ACTIVE_CLIENT_THRESHOLD and
                peer.get("endpoint")):
                ip_only = peer["endpoint"].split(":")[0]  # Extract IP without port
                active_ips.add(ip_only)
                inbound_bytes += peer["rx"]
                outbound_bytes += peer["tx"]

        active_clients = len(active_ips)
        logging.info(f"WireGuard: {active_clients} live connected IPs: {', '.join(active_ips)}")

        return {
            "connection_type": config["vpn_type"],
            "active_clients": active_clients,
            "inbound_bytes": inbound_bytes,
            "outbound_bytes": outbound_bytes,
            "protocol": config["protocol"],
            "status_log": "wg show"
        }
    except Exception as e:
        logging.error(f"Exception in get_wireguard_info: {e}")
        return None

async def get_server_info(config):
    global prev_inbound, prev_outbound, prev_rx_packets, prev_tx_packets, prev_time, history
    try:
        try:
            subprocess.check_output(["ip", "link", "show", config["network_adapter"]], stderr=subprocess.STDOUT).decode()
            logging.info(f"Network adapter {config['network_adapter']} exists")
        except subprocess.CalledProcessError as e:
            logging.error(f"Network adapter {config['network_adapter']} does not exist: {e.output.decode()}")
            return None

        for attempt in range(5):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get('https://api.ipify.org', timeout=5) as resp:
                        server_ip = await resp.text()
                logging.info(f"Retrieved server IP: {server_ip}")
                break
            except Exception as e:
                logging.warning(f"Failed to get server IP, attempt {attempt + 1}: {e}")
                if attempt == 4:
                    return None
                await asyncio.sleep(2)

        if config["vpn_type"] == "Openvpn":
            vpn_raw = await get_openvpn_info(config)
        elif config["vpn_type"] == "Wireguard":
            vpn_raw = await get_wireguard_info(config)
        else:
            vpn_raw = None

        if not vpn_raw:
            logging.error("No VPN data retrieved")
            return None

        try:
            ip_output = subprocess.check_output(["ip", "-s", "link", "show", config["network_adapter"]], stderr=subprocess.STDOUT).decode()
            logging.debug(f"ip -s link show {config['network_adapter']} output:\n{ip_output}")
        except Exception as e:
            logging.error(f"Failed to get ip link stats for {config['network_adapter']}: {e}")
            return None

        lines = ip_output.splitlines()
        rx_packets = 0
        tx_packets = 0
        rx_index = None
        for i, line in enumerate(lines):
            if line.strip().startswith("RX:"):
                rx_index = i
                break
        if rx_index is not None:
            rx_line = lines[rx_index + 1].strip().split()
            if len(rx_line) >= 2:
                rx_packets = int(rx_line[1])
        tx_index = rx_index + 2 if rx_index is not None else None
        if tx_index and tx_index < len(lines) and lines[tx_index].strip().startswith("TX:"):
            tx_line = lines[tx_index + 1].strip().split()
            if len(tx_line) >= 2:
                tx_packets = int(tx_line[1])

        now = datetime.datetime.now()
        inbound = outbound = "N/A"
        pps_in = pps_out = 0
        if prev_time:
            time_diff = (now - prev_time).total_seconds()
            if time_diff > 0:
                in_diff = vpn_raw["inbound_bytes"] - prev_inbound
                out_diff = vpn_raw["outbound_bytes"] - prev_outbound
                in_mbps = max(0, (in_diff * 8 / 1_000_000) / time_diff)
                out_mbps = max(0, (out_diff * 8 / 1_000_000) / time_diff)
                inbound = f"{in_mbps:.2f} Mbps"
                outbound = f"{out_mbps:.2f} Mbps"
                if in_diff < 0 or out_diff < 0:
                    logging.info(f"Negative bandwidth: in_diff={in_diff}, out_diff={out_diff}")

                pps_in = max(0, (rx_packets - prev_rx_packets) / time_diff)
                pps_out = max(0, (tx_packets - prev_tx_packets) / time_diff)

        prev_inbound = vpn_raw["inbound_bytes"]
        prev_outbound = vpn_raw["outbound_bytes"]
        prev_rx_packets = rx_packets
        prev_tx_packets = tx_packets
        prev_time = now

        vpn_info = {
            "connection_type": vpn_raw["connection_type"],
            "active_clients": vpn_raw["active_clients"],
            "outbound": outbound,
            "inbound": inbound,
            "protocol": vpn_raw["protocol"],
            "pps_in": pps_in,
            "pps_out": pps_out,
            "status_log": vpn_raw["status_log"]
        }

        history.append({
            "time": now,
            "in_mbps": float(inbound.split()[0]) if inbound != "N/A" else 0,
            "out_mbps": float(outbound.split()[0]) if outbound != "N/A" else 0,
            "pps_in": pps_in,
            "pps_out": pps_out,
            "users": vpn_info["active_clients"]
        })
        history = history[-MAX_HISTORY_POINTS:]

        uk_tz = pytz.timezone('Europe/London')
        timestamp = datetime.datetime.now(uk_tz).strftime("%d/%m/%Y %H:%M:%S")
        masked_ip = re.sub(r"(\d+\.\d+\.\d+\.)(\d+)", r"\1***", server_ip)

        logging.info(f"Server info retrieved: {vpn_info['connection_type']}, {vpn_info['active_clients']} clients, {inbound} in, {outbound} out")

        return {
            "server_ip": masked_ip,
            "vpn_info": vpn_info,
            "last_updated": timestamp,
            "uptime": get_system_uptime(),
            "location": config["server_location"],
            "protocol": config["protocol"]
        }
    except Exception as e:
        logging.error(f"Exception in get_server_info: {e}")
        return None

def generate_graph(history):
    if not history:
        logging.warning("No history data for graph")
        return None

    times = [d["time"] for d in history]
    in_mbps = [d["in_mbps"] for d in history]
    out_mbps = [d["out_mbps"] for d in history]
    pps_in = [d["pps_in"] for d in history]
    pps_out = [d["pps_out"] for d in history]
    users = [d["users"] for d in history]

    fig, ax1 = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor('darkgray')
    ax1.set_facecolor('black')
    ax1.plot(times, in_mbps, color='blue', label='Inbound (Mbps)')
    ax1.plot(times, out_mbps, color='green', label='Outbound (Mbps)')
    ax1.set_xlabel('Time', color='white')
    ax1.set_ylabel('Bandwidth (Mbps)', color='white')
    ax1.tick_params(axis='x', colors='white', rotation=45)
    ax1.tick_params(axis='y', colors='white')
    ax1.grid(True, color='gray')

    ax2 = ax1.twinx()
    ax2.set_facecolor('black')
    ax2.plot(times, pps_in, color='cyan', label='PPS In')
    ax2.plot(times, pps_out, color='magenta', label='PPS Out')
    ax2.plot(times, users, color='red', label='Connected Users')
    ax2.set_ylabel('PPS / Users', color='white')
    ax2.tick_params(axis='y', colors='white')

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', labelcolor='white', facecolor='black')

    plt.title('VPN Metrics Over Time', color='white')
    buf = BytesIO()
    plt.savefig(buf, format='png', facecolor=fig.get_facecolor(), bbox_inches='tight')
    plt.close()
    buf.seek(0)
    logging.info("Generated graph PNG")
    return buf

async def update_status(config, channel):
    info = await get_server_info(config)
    if not info or not info["vpn_info"]:
        logging.warning("No server info retrieved for status update")
        return None, None

    embed_title = f"JVPN {info['location']} Status"
    embed = discord.Embed(title=embed_title, color=0x00ff00)
    embed.add_field(name="Server IP", value=info["server_ip"], inline=False)
    embed.add_field(name="Connection Type", value=info["vpn_info"]["connection_type"], inline=False)
    embed.add_field(name="Protocol", value=info["protocol"], inline=False)
    embed.add_field(name="Active VPN Clients (Live Connected IPs)", value=info["vpn_info"]["active_clients"], inline=False)
    embed.add_field(name="Outbound (over 60s)", value=info["vpn_info"]["outbound"], inline=True)
    embed.add_field(name="Inbound (over 60s)", value=info["vpn_info"]["inbound"], inline=True)
    embed.add_field(name="PPS In (over 60s)", value=f"{info['vpn_info']['pps_in']:.2f}", inline=True)
    embed.add_field(name="PPS Out (over 60s)", value=f"{info['vpn_info']['pps_out']:.2f}", inline=True)
    embed.add_field(name="System Uptime", value=info["uptime"], inline=False)
    embed.add_field(name="Last Updated", value=info["last_updated"], inline=False)
    embed.set_footer(text=f"Updates every {REFRESH_INTERVAL} seconds")

    graph_buf = generate_graph(history)
    files = []
    if graph_buf:
        files.append(discord.File(fp=graph_buf, filename='vpn_graph.png'))
        embed.set_image(url="attachment://vpn_graph.png")

    return embed, files

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')
    config = bot.config
    channel = bot.get_channel(config["channel_id"])
    if not channel:
        logging.error(f"Channel with ID {config['channel_id']} not found")
        print(f"Channel with ID {config['channel_id']} not found. Exiting.")
        await bot.close()
        return

    bot_perms = channel.permissions_for(channel.guild.me)
    required_perms = [
        bot_perms.send_messages,
        bot_perms.attach_files,
        bot_perms.embed_links,
        bot_perms.read_messages,
        bot_perms.read_message_history
    ]
    if not all(required_perms):
        missing = []
        if not bot_perms.send_messages:
            missing.append("send_messages")
        if not bot_perms.attach_files:
            missing.append("attach_files")
        if not bot_perms.embed_links:
            missing.append("embed_links")
        if not bot_perms.read_messages:
            missing.append("read_messages")
        if not bot_perms.read_message_history:
            missing.append("read_message_history")
        logging.error(f"Bot lacks required permissions in channel {config['channel_id']}: {', '.join(missing)}")
        print(f"Bot lacks permissions: {', '.join(missing)}. Exiting.")
        await bot.close()
        return

    logging.info(f"Bot has required permissions in channel {config['channel_id']}")
    print(f"Bot has permissions to post in channel {config['channel_id']}")

    message = None
    message_id = None
    if os.path.exists(MESSAGE_ID_FILE):
        try:
            with open(MESSAGE_ID_FILE, "r") as f:
                data = json.load(f)
                message_id = data.get("message_id")
            logging.info(f"Read message ID {message_id} from file")
        except Exception as e:
            logging.warning(f"Failed to read message ID file: {e}")

    if message_id:
        try:
            message = await channel.fetch_message(message_id)
            logging.info(f"Fetched existing message {message_id}")
        except Exception as e:
            logging.warning(f"Could not fetch previous message {message_id}: {e}")
            message = None

    while True:
        embed, files = await update_status(config, channel)
        if not embed:
            await asyncio.sleep(REFRESH_INTERVAL)
            continue

        try:
            if message is None:
                message = await channel.send(embed=embed, files=files)
                with open(MESSAGE_ID_FILE, "w") as f:
                    json.dump({"message_id": message.id}, f)
                logging.info(f"Sent initial message with ID {message.id}")
            else:
                await message.edit(embed=embed, attachments=files)
                logging.info(f"Edited existing message with ID {message.id}")
        except Exception as e:
            logging.error(f"Failed to send/edit message: {e}")
            message = None

        await asyncio.sleep(REFRESH_INTERVAL)

@bot.command(name='status')
async def force_status(ctx):
    if ctx.channel.id != bot.config["channel_id"]:
        await ctx.send("This command can only be used in the configured channel.")
        return
    logging.info("Forcing status update via !status command")
    channel = ctx.channel
    config = bot.config
    embed, files = await update_status(config, channel)
    if not embed:
        error_msg = "Failed to retrieve server info for status update."
        if config["vpn_type"] == "Openvpn":
            service_status = check_openvpn_service()
            if not service_status:
                error_msg += " No OpenVPN service or process is running. Start it with 'systemctl start openvpn-server@server' or check 'systemctl | grep openvpn'."
            else:
                status_log = None
                for path in OPENVPN_STATUS_PATHS:
                    if os.path.exists(path):
                        status_log = path
                        break
                if not status_log:
                    error_msg += f" No OpenVPN status log found in {', '.join(OPENVPN_STATUS_PATHS)}. Ensure 'status' directive is in your OpenVPN config."
                elif not os.access(status_log, os.R_OK):
                    error_msg += f" OpenVPN status log {status_log} is not readable. Check permissions with 'chmod +r {status_log}'."
                else:
                    try:
                        with open(status_log, "r") as f:
                            if not f.read().strip():
                                error_msg += f" OpenVPN status log {status_log} is empty. Check OpenVPN logs with 'journalctl -u openvpn-server@server' or 'ps aux | grep openvpn'."
                        log_mtime = os.path.getmtime(status_log)
                        current_time = datetime.datetime.now().timestamp()
                        if current_time - log_mtime > STATUS_LOG_MAX_AGE:
                            error_msg += f" OpenVPN status log {status_log} is outdated (last modified {int(current_time - log_mtime)}s ago). Restart OpenVPN."
                    except:
                        pass
        elif config["vpn_type"] == "Wireguard":
            try:
                subprocess.check_output(["wg", "show", config["network_adapter"]], stderr=subprocess.STDOUT).decode()
            except subprocess.CalledProcessError as e:
                error_msg += f" WireGuard interface {config['network_adapter']} not found or 'wg' command failed: {e.output.decode()}"
        await ctx.send(error_msg)
        return

    message = None
    message_id = None
    if os.path.exists(MESSAGE_ID_FILE):
        try:
            with open(MESSAGE_ID_FILE, "r") as f:
                data = json.load(f)
                message_id = data.get("message_id")
        except Exception as e:
            logging.warning(f"Failed to read message ID file: {e}")

    if message_id:
        try:
            message = await channel.fetch_message(message_id)
            logging.info(f"Fetched existing message {message_id} for !status")
        except Exception as e:
            logging.warning(f"Could not fetch previous message {message_id}: {e}")
            message = None

    try:
        if message is None:
            message = await channel.send(embed=embed, files=files)
            with open(MESSAGE_ID_FILE, "w") as f:
                json.dump({"message_id": message.id}, f)
            logging.info(f"Sent new message with ID {message.id} for !status")
        else:
            await message.edit(embed=embed, attachments=files)
            logging.info(f"Edited message {message.id} for !status")
        await ctx.send("Status updated successfully!")
    except Exception as e:
        logging.error(f"Failed to update status for !status: {e}")
        await ctx.send(f"Failed to update status: {str(e)}")

@bot.command(name='debug')
async def debug(ctx):
    if ctx.channel.id != bot.config["channel_id"]:
        await ctx.send("This command can only be used in the configured channel.")
        return
    config = bot.config
    channel = bot.get_channel(config["channel_id"])
    perms = channel.permissions_for(channel.guild.me)
    service_status = check_openvpn_service() if config["vpn_type"] == "Openvpn" else "N/A"
    debug_info = (
        f"**Debug Info**\n"
        f"Bot: {bot.user}\n"
        f"Channel ID: {config['channel_id']}\n"
        f"VPN Type: {config['vpn_type']}\n"
        f"Network Adapter: {config['network_adapter']}\n"
        f"Location: {config['server_location']}\n"
        f"Protocol: {config['protocol']}\n"
        f"Permissions: Send Messages: {perms.send_messages}, Attach Files: {perms.attach_files}, "
        f"Embed Links: {perms.embed_links}, Read Messages: {perms.read_messages}, "
        f"Read Message History: {perms.read_message_history}\n"
        f"Message ID File Exists: {os.path.exists(MESSAGE_ID_FILE)}\n"
    )
    if config["vpn_type"] == "Openvpn":
        debug_info += f"OpenVPN Service/Process: {service_status}\n"
        status_log = None
        for path in OPENVPN_STATUS_PATHS:
            if os.path.exists(path):
                status_log = path
                break
        debug_info += f"OpenVPN Status Log: {status_log if status_log else 'Not found'}\n"
        debug_info += f"OpenVPN Log Exists: {os.path.exists(status_log) if status_log else False}\n"
        debug_info += f"OpenVPN Log Readable: {os.access(status_log, os.R_OK) if status_log and os.path.exists(status_log) else False}\n"
        if status_log and os.path.exists(status_log):
            try:
                log_mtime = os.path.getmtime(status_log)
                current_time = datetime.datetime.now().timestamp()
                debug_info += f"OpenVPN Log Last Modified: {int(current_time - log_mtime)}s ago\n"
            except:
                debug_info += "OpenVPN Log Last Modified: Unknown\n"
    else:
        debug_info += f"WireGuard Interface: {config['network_adapter']}\n"
        try:
            wg_output = subprocess.check_output(["wg", "show", config["network_adapter"]], stderr=subprocess.STDOUT).decode()
            debug_info += f"WireGuard Status: Active\nWireGuard Output:\n{wg_output}\n"
        except subprocess.CalledProcessError as e:
            debug_info += f"WireGuard Status: Not active ({e.output.decode()})\n"

    try:
        ip_output = subprocess.check_output(["ip", "link", "show", config["network_adapter"]], stderr=subprocess.STDOUT).decode()
        debug_info += f"Network Adapter Status: Exists\n{ip_output}"
    except subprocess.CalledProcessError as e:
        debug_info += f"Network Adapter Status: Does not exist\n{e.output.decode()}"

    await ctx.send(debug_info)
    logging.info(f"Debug command executed: {debug_info}")

def main():
    config = get_user_config()
    bot.config = config
    bot.run(config["bot_token"])

if __name__ == "__main__":
    main()
```