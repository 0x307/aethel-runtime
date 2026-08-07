//! # Storage Layer — HelixDB Vector-Graph Hybrid Database Adapter
//!
//! This module provides the storage layer for Aethel-Vault's encrypted state.
//! It wraps the **HelixDB** vector-graph hybrid database, which combines:
//!
//! - **Graph traversal**: Temporal trajectory edges between state nodes
//!   (`EVOLVED_TO` relationships)
//! - **Vector proximity search**: 256-dimensional HNSW approximate
//!   nearest-neighbor indexing over M-LWE coefficient vectors
//! - **Raft consensus**: Distributed replication across a 3-node minimum
//!   cluster with mTLS 1.3 inter-node security
//!
//! ## Architecture
//!
//! ```text
//! +------------------------------------------------------------------+
//! |                    HelixDB Cluster (3+ Nodes)                    |
//! |                                                                  |
//! |  HNSW Vector Index (d=256)  |  Graph Engine  |  Raft Consensus  |
//! |  Cosine Distance            |  Temporal Traj |  mTLS 1.3        |
//! |                                                                  |
//! |  API: HelixQL DSL | gRPC v3 | GraphQL v2026                     |
//! +------------------------------------------------------------------+
//! ```
//!
//! ## Modules
//!
//! - [`helixdb`] — HelixDB gRPC adapter. Provides [`helixdb::HelixDbAdapter`]
//!   for `UpsertStateNode`, `VectorProximitySearch`, and
//!   `TraverseTemporalTrajectory` operations.
//!
//! ## Security Properties
//!
//! - Attribute vectors stored in HelixDB are masked with homomorphic lattice
//!   noise to prevent exact scalar attribute recovery from proximity queries.
//! - Forward-private pruning: deleting a `StateNode` permanently renders all
//!   historical sub-graph trajectories mathematically un-navigable.
//! - All inter-node and client-to-cluster communication uses mTLS 1.3.
//!
//! ## Port Allocation
//!
//! | Service              | Port |
//! |----------------------|------|
//! | Envoy Proxy          | 443  |
//! | Aethel Gateway HTTP  | 8080 |
//! | Aethel Gateway gRPC  | 9090 |
//! | HelixDB Engine       | 7070 |
//! | HelixDB Raft         | 7071 |
//! | HelixDB Gossip       | 7072 |
//! | Prometheus           | 9100 |

/// HelixDB gRPC storage adapter.
///
/// Provides [`helixdb::HelixDbAdapter`] — the primary interface for storing
/// and querying encrypted vault state in the HelixDB vector-graph manifold.
pub mod helixdb;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use helixdb::HelixDbAdapter;
