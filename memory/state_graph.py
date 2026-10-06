"""
memory/state_graph.py — Application State Graph

Represents the explored surface of the target as a directed graph where:
  • Nodes  = distinct application views (URL + DOM summary + session state)
  • Edges  = UI actions taken to transition between views

Persisted to SQLite so exploration can be resumed across restarts.

Why NetworkX?
  Built-in algorithms (BFS, shortest path, betweenness centrality) let
  the Mutator agent prioritise high-value endpoints without extra code.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass, asdict, field
from typing import Any, Optional

import networkx as nx

from config import config

logger = logging.getLogger("StateGraph")


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ViewNode:
    url:                    str
    dom_summary:            str          # LLM-generated summary for display
    session_state:          dict         # cookies / localStorage snapshot at this view
    structural_fingerprint: str = ""     # Hash of the raw accessibility-tree snapshot
    node_id:                str = ""     # SHA-256(url + structural_fingerprint)
    visit_count:            int = 0

    def __post_init__(self):
        if not self.node_id:
            digest = hashlib.sha256(
                (self.url + self.structural_fingerprint).encode()
            ).hexdigest()[:16]
            self.node_id = digest


@dataclass
class ActionEdge:
    source_id:   str
    target_id:   str
    action_type: str            # "click" | "type" | "navigate" | "form_submit"
    action_ref:  str            # accessibility ref or URL
    payload:     dict = field(default_factory=dict)  # form data / request body


# ── Graph class ───────────────────────────────────────────────────────────────

class StateGraph:
    """
    Directed multi-graph of application state.

    Thread-safety: designed for single async-event-loop use; SQLite writes
    happen synchronously (fast enough for a scanner).
    """

    def __init__(self, db_path: str = config.SQLITE_DB_PATH):
        self.graph: nx.DiGraph = nx.DiGraph()
        self._db_path = db_path
        self._init_db()
        self._load_from_db()
        logger.info("StateGraph initialised (%d nodes).", self.graph.number_of_nodes())

    # ── Public API ────────────────────────────────────────────────────────────

    def add_node(self, node: ViewNode) -> str:
        """
        Upsert a ViewNode.  Returns the node_id.
        If the node already exists, increments its visit_count.
        """
        if self.graph.has_node(node.node_id):
            self.graph.nodes[node.node_id]["visit_count"] += 1
        else:
            self.graph.add_node(node.node_id, **asdict(node))
            self._persist_node(node)

        return node.node_id

    def add_edge(self, edge: ActionEdge) -> None:
        """
        Add a directed edge between two ViewNodes.
        Multiple edges between the same nodes are allowed (different actions).
        """
        if not self.graph.has_node(edge.source_id):
            raise ValueError(f"Source node {edge.source_id} not in graph.")
        if not self.graph.has_node(edge.target_id):
            raise ValueError(f"Target node {edge.target_id} not in graph.")

        self.graph.add_edge(
            edge.source_id,
            edge.target_id,
            action_type=edge.action_type,
            action_ref=edge.action_ref,
            payload=json.dumps(edge.payload),
        )
        self._persist_edge(edge)

    def get_node(self, node_id: str) -> Optional[dict]:
        if self.graph.has_node(node_id):
            return dict(self.graph.nodes[node_id])
        return None

    def find_by_url(self, url: str) -> Optional[dict]:
        for nid, data in self.graph.nodes(data=True):
            if data.get("url") == url:
                return {"node_id": nid, **data}
        return None

    def all_nodes(self) -> list[dict]:
        return [{"node_id": nid, **data}
                for nid, data in self.graph.nodes(data=True)]

    def all_edges(self) -> list[dict]:
        edges = []
        for src, dst, data in self.graph.edges(data=True):
            edges.append({
                "source": src,
                "target": dst,
                **data,
                "payload": json.loads(data.get("payload", "{}")),
            })
        return edges

    def get_api_endpoints(self) -> list[dict]:
        """
        Return edges that carried HTTP API payloads —
        these are the prime targets for the Mutator agent.
        """
        return [
            e for e in self.all_edges()
            if e.get("payload") and e["action_type"] in {"form_submit", "api_call"}
        ]

    def summary(self) -> dict:
        return {
            "nodes":     self.graph.number_of_nodes(),
            "edges":     self.graph.number_of_edges(),
            "endpoints": len(self.get_api_endpoints()),
        }

    def export_json(self) -> str:
        """Serialise the full graph for debugging / reporting."""
        return json.dumps({
            "nodes": self.all_nodes(),
            "edges": self.all_edges(),
        }, indent=2)

    # ── SQLite persistence ────────────────────────────────────────────────────

    def _init_db(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id      TEXT PRIMARY KEY,
                    url          TEXT,
                    dom_summary  TEXT,
                    session_state TEXT,
                    structural_fingerprint TEXT DEFAULT '',
                    visit_count  INTEGER DEFAULT 0
                )
            """)
            existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(nodes)")}
            if "structural_fingerprint" not in existing_cols:
                conn.execute(
                    "ALTER TABLE nodes ADD COLUMN structural_fingerprint TEXT DEFAULT ''"
                )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS edges (
                    source_id   TEXT,
                    target_id   TEXT,
                    action_type TEXT,
                    action_ref  TEXT,
                    payload     TEXT,
                    PRIMARY KEY (source_id, target_id, action_ref)
                )
            """)
            conn.commit()

    def _load_from_db(self):
        with sqlite3.connect(self._db_path) as conn:
            for row in conn.execute(
                "SELECT node_id, url, dom_summary, session_state, "
                "structural_fingerprint, visit_count FROM nodes"
            ):
                node_id, url, dom_summary, session_state, fingerprint, visit_count = row
                self.graph.add_node(node_id,
                    node_id=node_id,
                    url=url,
                    dom_summary=dom_summary,
                    session_state=json.loads(session_state or "{}"),
                    structural_fingerprint=fingerprint or "",
                    visit_count=visit_count,
                )

            for row in conn.execute("SELECT * FROM edges"):
                src, dst, atype, aref, payload = row
                self.graph.add_edge(src, dst,
                    action_type=atype,
                    action_ref=aref,
                    payload=payload or "{}",
                )

    def _persist_node(self, node: ViewNode):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO nodes
                    (node_id, url, dom_summary, session_state,
                     structural_fingerprint, visit_count)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                node.node_id, node.url, node.dom_summary,
                json.dumps(node.session_state), node.structural_fingerprint,
                node.visit_count,
            ))
            conn.commit()

    def _persist_edge(self, edge: ActionEdge):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO edges
                    (source_id, target_id, action_type, action_ref, payload)
                VALUES (?, ?, ?, ?, ?)
            """, (
                edge.source_id, edge.target_id,
                edge.action_type, edge.action_ref,
                json.dumps(edge.payload),
            ))
            conn.commit()
