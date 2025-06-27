# load config helper
from server import config
import requests

# base url of the main api server
MAIN_SERVER_URL = config.get("TUNNELITE_SERVER_URL", "https://api.tunnelite.net")

def get_public_ip():
    """auto-detect public ip address"""
    try:
        # try multiple services for reliability
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me",
            "https://icanhazip.com"
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    return response.text.strip()
            except:
                continue
        
        # fallback: try to detect from local network interfaces
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
        
    except Exception as e:
        print(f"warn:     could not auto-detect public ip: {e}")
        return "127.0.0.1"  # fallback

# auto-detect public ip and port will be set dynamically
PUBLIC_IP = get_public_ip()
NODE_PUBLIC_ADDRESS = None  # will be set dynamically with actual port

def set_node_public_address(port: int):
    """set the node public address with the actual running port"""
    global NODE_PUBLIC_ADDRESS  # declare global before any usage
    NODE_PUBLIC_ADDRESS = f"https://{PUBLIC_IP}:{port}"
    print(f"info:     node public address set to: {NODE_PUBLIC_ADDRESS}")
    return NODE_PUBLIC_ADDRESS
