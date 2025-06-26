import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from server.logger import log

class NodeConnectionManager:
    """manages persistent websocket connections from tunnel nodes."""
    def __init__(self):
        # maps a node's secret id to its active websocket connection
        self.active_node_connections: dict[str, WebSocket] = {}

    async def connect(self, node_secret_id: str, websocket: WebSocket):
        """registers a new node connection."""
        await websocket.accept()
        self.active_node_connections[node_secret_id] = websocket
        log.info("node control channel connected", extra={"node_secret_id": node_secret_id})

    def disconnect(self, node_secret_id: str):
        """removes a node connection."""
        if node_secret_id in self.active_node_connections:
            del self.active_node_connections[node_secret_id]
            log.info("node control channel disconnected", extra={"node_secret_id": node_secret_id})

    async def send_message_to_node(self, node_secret_id: str, message: dict) -> bool:
        """sends a json message to a specific node."""
        if node_secret_id in self.active_node_connections:
            websocket = self.active_node_connections[node_secret_id]
            try:
                await websocket.send_json(message)
                return True
            except Exception:
                log.error(
                    "failed to send message to node control channel",
                    extra={"node_secret_id": node_secret_id},
                    exc_info=True
                )
                # connection might be broken, disconnect it
                self.disconnect(node_secret_id)
        return False


# create a shared instance for the application to use
node_manager = NodeConnectionManager()

# create the router for this component
router = APIRouter(tags=["node control"])


@router.websocket("/ws/node-control")
async def node_control_websocket(websocket: WebSocket):
    """
    this endpoint handles the persistent control channel from each tunnel node.
    nodes connect here to receive real-time commands from the server.
    """
    node_secret_id = None
    try:
        # the first message from the node must be an auth message
        auth_message = await websocket.receive_json()
        if auth_message.get("type") != "auth":
            await websocket.close(code=1008, reason="auth message required")
            return

        node_secret_id = auth_message.get("node_secret_id")
        if not node_secret_id:
            await websocket.close(code=1008, reason="node_secret_id is required for auth")
            return

        await node_manager.connect(node_secret_id, websocket)

        # keep the connection open to listen for disconnect
        while True:
            # this is a one-way channel (server -> node), so we just wait.
            # a client-side disconnect will raise WebSocketDisconnect here.
            await websocket.receive_text()

    except WebSocketDisconnect:
        if node_secret_id:
            node_manager.disconnect(node_secret_id)
    except Exception:
        log.error(
            "an unexpected error occurred in the node control websocket",
            extra={"node_secret_id": node_secret_id},
            exc_info=True
        )
        if node_secret_id:
            node_manager.disconnect(node_secret_id)
