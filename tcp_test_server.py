#!/usr/bin/env python3
"""
Simple TCP test server for testing tunnelite TCP tunnels.
Usage: python tcp_test_server.py [port]
"""

import socket
import sys
import threading
import time

def handle_client(client_socket, client_address):
    """Handle a single client connection"""
    print(f"[{time.strftime('%H:%M:%S')}] New connection from {client_address}")
    
    try:
        while True:
            # Receive data from client
            data = client_socket.recv(1024)
            if not data:
                break
                
            print(f"[{time.strftime('%H:%M:%S')}] Received {len(data)} bytes: {data[:50]}...")
            
            # Echo the data back with a prefix
            response = b"ECHO: " + data
            client_socket.send(response)
            print(f"[{time.strftime('%H:%M:%S')}] Sent {len(response)} bytes back")
            
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Error handling client {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"[{time.strftime('%H:%M:%S')}] Connection from {client_address} closed")

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 50000
    
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Bind and listen
        server_socket.bind(('127.0.0.1', port))
        server_socket.listen(5)
        print(f"TCP test server listening on 127.0.0.1:{port}")
        print("Waiting for connections... (Ctrl+C to stop)")
        
        while True:
            # Accept connection
            client_socket, client_address = server_socket.accept()
            
            # Handle client in a separate thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True
            )
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\nShutting down server...")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main() 