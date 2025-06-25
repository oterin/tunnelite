from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active_tunnels: dict[str, WebSocket] = {}

    async def connect(
        self,
        public_hostname: str,
        websocket: WebSocket
    ):
        await websocket.accept()
        self.active_tunnels[public_hostname] = websocket
        print(f"info:     tunnel activated for {public_hostname}")

    def disconnect(
        self,
        public_hostname: str
    ):
        if public_hostname in self.active_tunnels:
            del self.active_tunnels[public_hostname]
            print(f"info:     tunnel deactivated for {public_hostname}")

        async def send_to_client(
            self,
            public_hostname: str,
            data: bytes
        ):
            if public_hostname in self.active_tunnels:
                websocket = self.active_tunnels[public_hostname]
                await websocket.send_bytes(data)

manager = ConnectionManager()
