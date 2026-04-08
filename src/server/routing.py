import time
from collections import deque
from typing import Dict, Set, Any


class State:
    def __init__(self, server_id: str):
        self.server_id = server_id

        # Users connected to THIS server
        self.local_users: Set[str] = set()              # usernames
        self.user_ws: Dict[str, Any] = {}               # user -> websocket

        # Known location of users across the overlay: user -> server_id
        # For local users, server_id == self.server_id
        self.user_locations: Dict[str, str] = {}

        # Known peer servers we’re connected to: server_id -> websocket
        self.peers: Dict[str, Any] = {}

        # Deduplication for broadcast and relayed deliveries
        self.seen_ids = deque(maxlen=10000)             # message ids
        self.last_hb = int(time.time())

    def mark_seen(self, msg_id: str) -> bool:
        """Return True if already seen; otherwise record and return False."""
        if msg_id in self.seen_ids:
            return True
        self.seen_ids.append(msg_id)
        return False
