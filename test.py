#!/usr/bin/env python3

import asyncio
import requests
import websockets
import json
import ssl

SERVER_URL = "https://api.tunnelite.net"
WS_URL = "wss://api.tunnelite.net"

async def test_registration_router():
    """test if registration router is included"""
    print("1. testing registration router...")
    try:
        response = requests.get(f"{SERVER_URL}/registration/test", verify=False)
        print(f"   status: {response.status_code}")
        print(f"   response: {response.text}")
    except Exception as e:
        print(f"   error: {e}")

async def test_basic_websocket():
    """test if websockets work at all"""
    print("\n2. testing basic websocket...")
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with websockets.connect(f"{WS_URL}/test-ws", ssl=ssl_context) as ws:
            message = await ws.recv()
            print(f"   success: {message}")
    except Exception as e:
        print(f"   error: {e}")

async def test_registration_websocket():
    """test the actual registration websocket"""
    print("\n3. testing registration websocket...")
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with websockets.connect(f"{WS_URL}/ws/register-node", ssl=ssl_context) as ws:
            print("   websocket connected!")
            
            # send auth data
            auth_data = {
                "node_secret_id": "test-node-id",
                "admin_key": "WooYeahOhYeahWooYeah"
            }
            await ws.send(json.dumps(auth_data))
            print("   auth data sent")
            
            # wait for response
            response = await ws.recv()
            print(f"   response: {response}")
            
    except Exception as e:
        print(f"   error: {e}")

async def main():
    print("tunnelite websocket diagnostics")
    print("=" * 40)
    
    await test_registration_router()
    await test_basic_websocket()  
    await test_registration_websocket()
    
    print("\ntest complete!")

if __name__ == "__main__":
    asyncio.run(main()) 