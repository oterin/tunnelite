import asyncio
import json
import random
import secrets
import time
from typing import List
from random_word import RandomWords

import requests
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Response, Header
from starlette.responses import StreamingResponse


from server.components import database
from server.logger import log
# load config
from server import config
from server import security

router = APIRouter(prefix="/registration", tags=["node registration"])

ADMIN_API_KEY = config.get("TUNNELITE_ADMIN_KEY")
if not ADMIN_API_KEY:
    raise ValueError("TUNNELITE_ADMIN_KEY not configured")

# debug flag to skip port verification (useful for testing behind NAT/firewall)
SKIP_PORT_VERIFICATION = config.get("SKIP_PORT_VERIFICATION", "false").lower() == "true"

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


# --- reverse benchmark endpoints ---

@router.get("/benchmark/download")
async def benchmark_download():
    """returns a large payload for the node to download to test its speed."""
    async def dummy_generator():
        for _ in range(BENCHMARK_PAYLOAD_SIZE // 1024):
            yield b'\0' * 1024
    return StreamingResponse(dummy_generator(), media_type="application/octet-stream")

@router.post("/benchmark/upload")
async def benchmark_upload(content_length: int = Header(...)):
    """receives a large payload from the node to test its upload speed."""
    # we don't need to actually read the body, just know it was sent.
    # the content-length header is sufficient.
    return Response(status_code=200, content=f"received {content_length} bytes.")


@router.websocket("/ws/register-node")
async def register_node_websocket(websocket: WebSocket):
    log.info("registration websocket connection attempt")
    node_secret_id = None
    
    try:
        log.info("about to accept websocket")
        await websocket.accept()
        log.info("registration websocket accepted, waiting for data")
        
        # 1. initial handshake and admin authentication
        data = await websocket.receive_json()
        log.info("registration websocket received data", extra={"data": data})
        
        node_secret_id = data.get("node_secret_id")
        admin_key = data.get("admin_key")
        
        log.info("checking admin key", extra={"received_key": admin_key, "expected_key": ADMIN_API_KEY})

        if admin_key != ADMIN_API_KEY:
            log.error("admin key mismatch!", extra={"received": admin_key, "expected": ADMIN_API_KEY})
            raise WebSocketDisconnect(code=1008, reason="invalid admin key.")

        if not node_secret_id:
            log.error("no node_secret_id provided")
            raise WebSocketDisconnect(code=1008, reason="node_secret_id is required.")

        node_record = database.get_node_by_secret_id(node_secret_id)
        log.info("node record lookup", extra={"node_secret_id": node_secret_id, "found": node_record is not None})
        if not node_record:
            log.warning("node record not found during registration", extra={"node_secret_id": node_secret_id})
            raise WebSocketDisconnect(code=1008, reason="node not registered (send heartbeat first)")

        node_ip = websocket.client.host # type: ignore
        database.upsert_node({"node_secret_id": node_secret_id, "status": "benchmarking", "verified_ip_address": node_ip})

        # 2. reverse bandwidth benchmark
        # tell the client to start the benchmark. it will connect to our http endpoints.
        await websocket.send_json({"type": "reverse_benchmark"})

        # wait for the client to send back its measured results
        benchmark_results = await websocket.receive_json()
        down_mbps = benchmark_results.get("down_mbps", 0)
        up_mbps = benchmark_results.get("up_mbps", 0)

        await websocket.send_json({"type": "info", "message": f"benchmark results received: {down_mbps:.2f} mbps down / {up_mbps:.2f} mbps up."})

        # 3. Interactive Configuration
        recommendation = int(down_mbps / 2) # assuming 2mbps

        await websocket.send_json({"type": "prompt", "message": f"we recommend a maximum of {recommendation} clients. enter max concurrent clients:"})
        max_clients = (await websocket.receive_json())["response"]

        await websocket.send_json({"type": "prompt", "message": "enter public port range for tcp/udp tunnels (e.g., 3000-4000; 5001):"})
        port_range_str = (await websocket.receive_json())["response"]
        ports_to_verify = parse_port_range(port_range_str)

        # 4. multi-port verification with concurrent challenges
        if SKIP_PORT_VERIFICATION:
            await websocket.send_json({"type": "info", "message": f"skipping port verification (debug mode) for {len(ports_to_verify)} ports..."})
            # just validate that the port range is parsed correctly
            for port in ports_to_verify:
                await websocket.send_json({"type": "info", "message": f"port {port} verified (skipped in debug mode)."})
        else:
            await websocket.send_json({"type": "info", "message": f"setting up challenge listeners on {len(ports_to_verify)} ports..."})
            
            # first, tell the node to set up all challenge listeners
            challenge_keys = {}
            for port in ports_to_verify:
                challenge_key = secrets.token_hex(8)
                challenge_keys[port] = challenge_key
                await websocket.send_json({
                    "type": "challenge",
                    "message": f"setting up listener on port {port}...",
                    "port": port,
                    "key": challenge_key
                })
                await websocket.receive_json() # wait for client readiness
            
            # give all listeners time to start
            await websocket.send_json({"type": "info", "message": "all listeners set up, starting verification..."})
            await asyncio.sleep(2)
            
            # now verify all ports concurrently with retries
            async def verify_port_with_retries(port: int, key: str) -> bool:
                verification_url = f"http://{node_ip}:{port}"
                for attempt in range(2):  # max 2 tries per port
                    try:
                        log.info(
                            "Verifying node port",
                            extra={"node_secret_id": node_secret_id, "url": verification_url, "attempt": attempt + 1}
                        )
                        res = requests.get(verification_url, timeout=8)  # longer timeout
                        if res.text == key:
                            return True
                        else:
                            log.warning(f"port {port} returned wrong key: expected {key}, got {res.text}")
                    except Exception as e:
                        log.warning(f"port {port} verification attempt {attempt + 1} failed: {e}")
                        if attempt < 1:  # if not the last attempt
                            await asyncio.sleep(2)  # wait before retry
                return False
            
            # run all verifications concurrently
            verification_tasks = [
                verify_port_with_retries(port, challenge_keys[port])
                for port in ports_to_verify
            ]
            results = await asyncio.gather(*verification_tasks, return_exceptions=True)
            
            # check results
            failed_ports = []
            for i, (port, result) in enumerate(zip(ports_to_verify, results)):
                if isinstance(result, Exception) or not result:
                    failed_ports.append(port)
                else:
                    await websocket.send_json({"type": "info", "message": f"port {port} verified successfully."})
            
            if failed_ports:
                raise WebSocketDisconnect(code=1011, reason=f"failed to verify ports: {failed_ports}")

        # 5. final approval
        # get country code from the verified geoip data already in the db
        geo_info = node_record.get("verified_geolocation", {})
        country_code = geo_info.get("countryCode", "local").lower()

        public_hostname = generate_unique_node_hostname(country_code)

        # generate node certificate for future auth
        node_cert = security.sign({
            "sub": node_secret_id,
            "role": "node",
            "hostname": public_hostname
        }, ttl=12*3600)  # 12 hours
        
        final_node_data = {
            "node_secret_id": node_secret_id,
            "public_hostname": public_hostname, # the official, server-assigned name
            "status": "approved",
            "node_cert": node_cert,
            "max_clients": int(max_clients),
            "port_range": port_range_str,
            "bandwidth_down_mbps": round(down_mbps, 2),
            "bandwidth_up_mbps": round(up_mbps, 2),
            "last_seen_at": time.time()
        }
        database.upsert_node(final_node_data)
        log.info(
            "Node registration successful",
            extra={"node_secret_id": node_secret_id, "public_hostname": public_hostname}
        )
        await websocket.send_json({
            "type": "success", 
            "message": f"node verified and approved! your public hostname is: {public_hostname}",
            "node_cert": node_cert
        })

    except WebSocketDisconnect as e:
        log.warning(
            "Node registration websocket disconnected",
            extra={"node_secret_id": node_secret_id, "reason": e.reason}
        )
    except Exception:
        log.error(
            "An unexpected error occurred during node registration",
            extra={"node_secret_id": node_secret_id},
            exc_info=True
        )
        if websocket.client_state.CONNECTED:
           await websocket.send_json({"type": "failure", "message": "An internal server error occurred."})
    except Exception as e:
        log.error(
            "websocket accept or early registration error", 
            extra={"error": str(e)},
            exc_info=True
        )

def generate_unique_node_hostname(country_code: str) -> str:
    r = RandomWords()
    for _ in range(20):
        word = r.get_random_word()
        hostname = f"{word}.{country_code}.tunnelite.ws"
        # there's no shot there's a node with this fragment
        # but if we put an infinite amount of monkeys in an
        # infinitely large room with ininite typewriters
        # eventually it is bound to create all the works of
        # shakespeare so i'd err on the side of caution 🤷🏻‍♂️
        if not any(hostname == n.get("public_hostname") for n in database.get_all_nodes()):
            return hostname

    # let's fallback to a random string
    return f"{secrets.token_hex(6)}.{country_code}.tunnelite.ws"
