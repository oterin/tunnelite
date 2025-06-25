import asyncio
import time
from .components import database
from .logger import log

# define thresholds for what "stale" means
PENDING_STALE_THRESHOLD_SECONDS = 900 # 15 minutes
ACTIVE_STALE_THRESHOLD_SECONDS = 300  # 5 minutes (node missed >2 heartbeats)

async def run_garbage_collection():
    log.info("running garbage collection for stale tunnels...")

    try:
        all_tunnels = database.get_all_tunnels()
        all_nodes = {node.get('node_id'): node for node in database.get_all_nodes()}

        tunnels_to_close = []

        for tunnel in all_tunnels:
            status = tunnel.get("status")
            if status not in ["pending", "active"]:
                continue

            tunnel_id = tunnel.get("tunnel_id")

            if status == "pending":
                created_at = tunnel.get("created_at", 0)
                if time.time() - created_at > PENDING_STALE_THRESHOLD_SECONDS:
                    log.warning(
                        "found stale pending tunnel. marking for closure.",
                        extra={"tunnel_id": tunnel_id, "age_seconds": time.time() - created_at}
                    )
                    tunnels_to_close.append(tunnel_id)

            elif status == "active":
                node_id = tunnel.get("node_id")
                node = all_nodes.get(node_id)

                if not node or time.time() - node.get("last_seen_at", 0) > ACTIVE_STALE_THRESHOLD_SECONDS:
                    log.warning(
                        "found active tunnel on a stale/offline node. marking for closure.",
                        extra={"tunnel_id": tunnel_id, "node_id": node_id}
                    )
                    tunnels_to_close.append(tunnel_id)

        if tunnels_to_close:
            for tunnel_id in tunnels_to_close:
                database.update_tunnel_status(tunnel_id, "closed_stale")
            log.info(
                "garbage collection finished.",
                extra={"tunnels_cleaned": len(tunnels_to_close)}
            )
        else:
            log.info("garbage collection finished. no stale tunnels found.")
    except Exception as e:
        log.error("an error occurred during garbage collection.", exc_info=True)


async def run_periodically(interval: int):
    while True:
        await run_garbage_collection()
        await asyncio.sleep(interval)
