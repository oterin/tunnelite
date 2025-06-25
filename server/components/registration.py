import asyncio
import json
import random
import secrets
import time
from typing import List
from random_word import RandomWords

import requests
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from server.components import database

router = APIRouter(tags=["node registration"])

BENCHMARK_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

def parse_port_range(range_str: str) -> List[int]:
    # format: <start>-<end>; <start>-<end>; ...
    ports = set()
    parts = [p.strip() for p in range_str.split(';')]
    for part in parts:
        if not part: continue
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

@router.websocket("/ws/register-node")
async def register_node_websocket(websocket: WebSocket):
    await websocket.accept()
    node_secret_id = None

    try:
        # 1. initial handshake
        data = await websocket.receive_json()
        node_secret_id = data.get("node_secret_id")
        if not node_secret_id:
            raise WebSocketDisconnect(code=1008, reason="node_secret_id is required.")

        node_record = database.get_node_by_secret_id(node_secret_id)
        if not node_record or not node_record.get("public_address"):
            raise WebSocketDisconnect(code=1008, reason=f"node has not registered its public_address yet. ensure the node is running and has sent a heartbeat.")

        node_api_url = node_record["public_address"]
        node_ip = websocket.client.host # type: ignore
        database.upsert_node({"node_secret_id": node_secret_id, "status": "benchmarking", "verified_ip_address": node_ip})

        # 2. bandwidth benchmark
        await websocket.send_json({"type": "benchmark", "payload_size": BENCHMARK_PAYLOAD_SIZE})
        await websocket.receive_json() # wait for client to confirm readiness

        benchmark_url = f"{node_api_url}/internal/run-benchmark"

        # test download speed (from node's perspective)
        start_time = time.time()
        res_down = requests.post(benchmark_url, data=bytes(BENCHMARK_PAYLOAD_SIZE), timeout=15)
        down_duration = time.time() - start_time
        down_mbps = (BENCHMARK_PAYLOAD_SIZE / down_duration) / (1024 * 1024) * 8

        # test upload speed (from node's perspective)
        start_time = time.time()
        res_up = requests.get(benchmark_url, timeout=15)
        up_duration = time.time() - start_time
        up_mbps = (len(res_up.content) / up_duration) / (1024 * 1024) * 8

        await websocket.send_json({"type": "info", "message": f"benchmark complete: {down_mbps:.2f} mbps down / {up_mbps:.2f} mbps up."})

        # 3. Interactive Configuration
        recommendation = int(down_mbps / 2) # assuming 2mbps

        await websocket.send_json({"type": "prompt", "message": f"we recommend a maximum of {recommendation} clients. enter max concurrent clients:"})
        max_clients = (await websocket.receive_json())["response"]

        await websocket.send_json({"type": "prompt", "message": "enter public port range for tcp/udp tunnels (e.g., 3000-4000; 5001):"})
        port_range_str = (await websocket.receive_json())["response"]
        ports_to_verify = parse_port_range(port_range_str)

        # 4. multi-port verification
        for port in ports_to_verify:
            challenge_key = secrets.token_hex(8)
            await websocket.send_json({
                "type": "challenge",
                "message": f"verifying port {port}...",
                "port": port,
                "key": challenge_key
            })
            await websocket.receive_json() # wait for client readiness

            await asyncio.sleep(1) # give listener a moment
            verification_url = f"http://{node_ip}:{port}"
            try:
                res = requests.get(verification_url, timeout=3)
                if res.text != challenge_key:
                    raise ValueError("incorrect key returned")
                await websocket.send_json({"type": "info", "message": f"port {port} verified."})
            except Exception as e:
                raise WebSocketDisconnect(code=1011, reason=f"failed to verify port {port}: {e}")

        # 5. final approval
        # get country code from the verified geoip data already in the db
        geo_info = node_record.get("verified_geolocation", {})
        country_code = geo_info.get("countryCode", "local").lower()

        public_hostname = generate_unique_node_hostname(country_code)

        final_node_data = {
            "node_secret_id": node_secret_id,
            "public_hostname": public_hostname, # the official, server-assigned name
            "status": "approved",
            "max_clients": int(max_clients),
            "port_range": port_range_str,
            "bandwidth_down_mbps": round(down_mbps, 2),
            "bandwidth_up_mbps": round(up_mbps, 2),
            "last_seen_at": time.time()
        }
        database.upsert_node(final_node_data)
        await websocket.send_json({"type": "success", "message": f"node verified and approved! your public hostname is: {public_hostname}"})

    except WebSocketDisconnect as e:
        print(f"node registration for {node_secret_id or 'unknown'} disconnected: {e.reason}")
    except Exception as e:
        print(f"an error occurred during node registration for {node_secret_id or 'unknown'}: {e}")
        if websocket.client_state.CONNECTED:
           await websocket.send_json({"type": "failure", "message": str(e)})

def generate_unique_node_hostname(country_code: str) -> str:
    r = RandomWords()
    for _ in range(20):
        word = r.get_random_word()
        hostname = f"{word}.{country_code}"
        # there's no shot there's a node with this fragment
        # but if we put an infinite amount of monkeys in an
        # infinitely large room with ininite typewriters
        # eventually it is bound to create all the works of
        # shakespeare so i'd err on the side of caution 🤷🏻‍♂️
        if not any(hostname == n.get("public_hostname") for n in database.get_all_nodes()):
            return hostname

    # let's fallback to a random string
    return f"{secrets.token_hex(6)}.{country_code}"
