//! # HelixDB Storage Adapter
//!
//! Rust adapter for the HelixDB vector-graph hybrid database.
//! Provides high-level methods for storing and querying encrypted vault state
//! in the HelixDB temporal manifold.
//!
//! ## Architecture
//!
//! HelixDB is a vector-graph hybrid database combining:
//! - **Graph traversal**: Temporal trajectory edges (`EVOLVED_TO`)
//! - **HNSW vector index**: 256-dimensional cosine distance proximity search
//! - **Raft consensus**: 3-node minimum cluster with mTLS 1.3
//!
//! ## Transport
//!
//! - **Native (`std` feature)**: tonic gRPC client over HTTP/2 with mTLS 1.3.
//!   Proto3 bindings generated from `proto/aethel_helix.proto` by `prost-build`.
//! - **WASM (`wasm32` target)**: HTTP/JSON stub that calls a JavaScript host
//!   function via `wasm_bindgen`. The actual HelixDB connection is handled by
//!   the wasmer.io host environment.
//!
//! ## Schema
//!
//! ```text
//! N::StateNode {
//!     node_id:           String,
//!     temporal_coord_t:  Float64,
//!     context_id:        String,
//!     attribute_mask:    Int32,
//!     h_commit:          Bytes,
//!     V::attr_vector:    Vector<Float32, 256>
//! }
//!
//! E::EVOLVED_TO {
//!     time_delta:        Float64,
//!     geodesic_distance: Float32
//! }
//! ```

use std::error::Error;
use std::fmt;

// ── Error Type ────────────────────────────────────────────────────────────────

/// Error type for HelixDB operations.
#[derive(Debug)]
pub enum HelixError {
    /// gRPC transport error.
    Transport(String),
    /// Serialization/deserialization error.
    Serialization(String),
    /// Invalid argument (e.g., wrong vector dimension).
    InvalidArgument(String),
    /// Node not found.
    NotFound(String),
    /// Operation not yet implemented (stub).
    NotImplemented(String),
}

impl fmt::Display for HelixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HelixError::Transport(msg) => write!(f, "HelixDB transport error: {}", msg),
            HelixError::Serialization(msg) => write!(f, "HelixDB serialization error: {}", msg),
            HelixError::InvalidArgument(msg) => write!(f, "HelixDB invalid argument: {}", msg),
            HelixError::NotFound(msg) => write!(f, "HelixDB not found: {}", msg),
            HelixError::NotImplemented(msg) => write!(f, "HelixDB not implemented: {}", msg),
        }
    }
}

impl Error for HelixError {}

// ── Shared Types ──────────────────────────────────────────────────────────────

/// A 256-element Float32 vector for HNSW proximity indexing.
///
/// Corresponds to `Vector256` in the proto3 definition.
/// Elements are normalized M-LWE polynomial coefficients in [-1.0, 1.0].
#[derive(Debug, Clone)]
pub struct Vector256 {
    /// Exactly 256 Float32 coefficients.
    pub elements: Vec<f32>,
}

impl Vector256 {
    /// Create a new `Vector256` from a slice of 256 Float32 values.
    ///
    /// # Panics
    ///
    /// Panics if `elements.len() != 256`.
    pub fn new(elements: Vec<f32>) -> Self {
        assert_eq!(elements.len(), 256, "Vector256 must have exactly 256 elements");
        Self { elements }
    }

    /// Normalize M-LWE i32 polynomial coefficients (in Z_q) to Float32 [-1, 1].
    ///
    /// Centered reduction: coefficients > Q/2 are mapped to negative range.
    pub fn from_mlwe_coeffs(coeffs: &[i32], q: i32) -> Self {
        assert_eq!(coeffs.len(), 256, "M-LWE coefficient vector must have 256 elements");
        let half_q = q / 2;
        let elements: Vec<f32> = coeffs
            .iter()
            .map(|&c| {
                let centered = if c > half_q { c - q } else { c };
                centered as f32 / half_q as f32
            })
            .collect();
        Self { elements }
    }

    /// Create a zero vector (useful for testing).
    pub fn zeros() -> Self {
        Self {
            elements: vec![0.0f32; 256],
        }
    }
}

/// Payload for a single state node upsert operation.
///
/// Corresponds to `StateNodeRequest` in the proto3 definition.
#[derive(Debug, Clone)]
pub struct StateNodePayload {
    /// 32-byte vault ID derived from PLP ephemeral projection.
    pub vault_id: [u8; 32],
    /// Bincode-serialized `FheUint64` ciphertext of the vault balance.
    pub ciphertext: Vec<u8>,
    /// Logical clock timestamp (Unix epoch milliseconds).
    pub timestamp: u64,
    /// 256-dimensional Float32 vector for HNSW proximity search.
    pub vector_embedding: Vector256,
    /// Optional previous node ID for `EVOLVED_TO` edge creation.
    pub previous_node_id: Option<String>,
    /// Geodesic distance from previous node (0.0 if first epoch).
    pub geodesic_distance: f32,
}

/// A state node with a cosine similarity score from a proximity search.
#[derive(Debug, Clone)]
pub struct ScoredStateNode {
    /// The matched state node.
    pub node_id: String,
    /// Cosine distance (lower = more similar).
    pub distance: f32,
}

// ── HelixDbAdapter ────────────────────────────────────────────────────────────

/// HelixDB storage adapter.
///
/// On native targets: wraps a tonic gRPC client (proto3 bindings from
/// `proto/aethel_helix.proto`).
///
/// On WASM targets: stub that serializes to JSON and calls a JavaScript host
/// function via `wasm_bindgen`.
///
/// # Example
///
/// ```rust,no_run
/// use aethel_vault::storage::helixdb::{HelixDbAdapter, StateNodePayload, Vector256};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let adapter = HelixDbAdapter::new(
///         "https://helix.aethel.network:9090",
///         None, None, None,
///     ).await?;
///
///     let node = StateNodePayload {
///         vault_id: [0u8; 32],
///         ciphertext: vec![0u8; 64],
///         timestamp: 1_000_000,
///         vector_embedding: Vector256::zeros(),
///         previous_node_id: None,
///         geodesic_distance: 0.0,
///     };
///
///     adapter.upsert_state_node(node).await?;
///     Ok(())
/// }
/// ```
pub struct HelixDbAdapter {
    /// gRPC endpoint URL (e.g., `https://helix.aethel.network:9090`)
    endpoint: String,
    // TODO: Replace with actual tonic gRPC client once proto3 bindings are wired:
    // client: helix_state_store_client::HelixStateStoreClient<tonic::transport::Channel>,
}

impl HelixDbAdapter {
    /// Create a new `HelixDbAdapter`.
    ///
    /// # Parameters
    ///
    /// - `endpoint`: gRPC endpoint URL (e.g., `https://helix.aethel.network:9090`)
    /// - `ca_cert_pem`: Optional PEM-encoded CA certificate for mTLS server verification
    /// - `client_cert_pem`: Optional PEM-encoded client certificate for mTLS
    /// - `client_key_pem`: Optional PEM-encoded client private key for mTLS
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS configuration is invalid or the gRPC
    /// channel cannot be established.
    pub async fn new(
        endpoint: &str,
        _ca_cert_pem: Option<&[u8]>,
        _client_cert_pem: Option<&[u8]>,
        _client_key_pem: Option<&[u8]>,
    ) -> Result<Self, Box<dyn Error>> {
        // TODO: Initialize tonic gRPC channel with mTLS 1.3 configuration:
        //
        // use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
        //
        // let mut tls_config = ClientTlsConfig::new();
        // if let Some(ca) = _ca_cert_pem {
        //     tls_config = tls_config.ca_certificate(Certificate::from_pem(ca));
        // }
        // if let (Some(cert), Some(key)) = (_client_cert_pem, _client_key_pem) {
        //     tls_config = tls_config.identity(Identity::from_pem(cert, key));
        // }
        //
        // let channel = Channel::from_shared(endpoint.to_string())?
        //     .tls_config(tls_config)?
        //     .connect()
        //     .await?;
        //
        // let client = HelixStateStoreClient::new(channel);

        Ok(Self {
            endpoint: endpoint.to_string(),
        })
    }

    /// Insert or update a vault state node in the HelixDB manifold.
    ///
    /// Creates an `EVOLVED_TO` edge from `node.previous_node_id` if provided.
    ///
    /// # Errors
    ///
    /// Returns a `HelixError` if the operation fails.
    pub async fn upsert_state_node(
        &self,
        node: StateNodePayload,
    ) -> Result<String, HelixError> {
        // TODO: Implement via tonic gRPC:
        //
        // use crate::storage::proto::aethel_helix::{StateNodeRequest};
        //
        // let request = tonic::Request::new(StateNodeRequest {
        //     vault_id: node.vault_id.to_vec(),
        //     ciphertext: node.ciphertext,
        //     timestamp: node.timestamp,
        //     vector_embedding: node.vector_embedding.elements,
        //     previous_node_id: node.previous_node_id.unwrap_or_default(),
        //     geodesic_distance: node.geodesic_distance,
        // });
        // let response = self.client.upsert_state_node(request).await
        //     .map_err(|e| HelixError::Transport(e.to_string()))?;
        // let inner = response.into_inner();
        // if inner.success {
        //     Ok(inner.node_id)
        // } else {
        //     Err(HelixError::Transport(inner.error_message))
        // }

        let _ = node;
        Err(HelixError::NotImplemented(format!(
            "upsert_state_node not yet wired to gRPC endpoint: {}",
            self.endpoint
        )))
    }

    /// Traverse the temporal trajectory graph from a vault's state nodes.
    ///
    /// Follows `EVOLVED_TO` edges up to `max_hops` depth, ordered by
    /// ascending timestamp.
    ///
    /// # Parameters
    ///
    /// - `vault_id`: 32-byte vault ID to traverse
    /// - `from_timestamp`: Start of temporal range (inclusive)
    /// - `to_timestamp`: End of temporal range (inclusive, 0 = no limit)
    /// - `max_hops`: Maximum number of `EVOLVED_TO` hops to follow
    ///
    /// # Returns
    ///
    /// Ordered list of state node payloads along the temporal trajectory.
    pub async fn traverse_temporal_trajectory(
        &self,
        vault_id: &[u8; 32],
        from_timestamp: u64,
        to_timestamp: u64,
        max_hops: u32,
    ) -> Result<Vec<StateNodePayload>, HelixError> {
        // TODO: Implement via tonic gRPC:
        //
        // let request = tonic::Request::new(TraversalRequest {
        //     vault_id: vault_id.to_vec(),
        //     from_timestamp,
        //     to_timestamp,
        //     max_hops,
        // });
        // let response = self.client.traverse_temporal_trajectory(request).await
        //     .map_err(|e| HelixError::Transport(e.to_string()))?;
        // Ok(response.into_inner().nodes.into_iter().map(|n| StateNodePayload {
        //     vault_id: n.vault_id.try_into().unwrap_or([0u8; 32]),
        //     ciphertext: n.ciphertext,
        //     timestamp: n.timestamp,
        //     vector_embedding: Vector256::new(n.vector_embedding),
        //     previous_node_id: if n.previous_node_id.is_empty() { None } else { Some(n.previous_node_id) },
        //     geodesic_distance: n.geodesic_distance,
        // }).collect())

        let _ = (vault_id, from_timestamp, to_timestamp, max_hops);
        Err(HelixError::NotImplemented(
            "traverse_temporal_trajectory not yet wired to gRPC".to_string(),
        ))
    }

    /// Execute a k-nearest-neighbor vector proximity search.
    ///
    /// Searches the HNSW vector index for the `top_k` nearest state nodes to
    /// `query_vector`, filtered by timestamp range.
    ///
    /// # Parameters
    ///
    /// - `query_vector`: 256-dimensional Float32 query vector
    /// - `top_k`: Number of nearest neighbors to return
    /// - `min_timestamp`: Minimum timestamp filter (0 = no lower bound)
    /// - `max_timestamp`: Maximum timestamp filter (0 = no upper bound)
    ///
    /// # Returns
    ///
    /// List of scored state nodes, ordered by ascending cosine distance.
    pub async fn vector_proximity_search(
        &self,
        query_vector: &Vector256,
        top_k: u32,
        min_timestamp: u64,
        max_timestamp: u64,
    ) -> Result<Vec<ScoredStateNode>, HelixError> {
        if query_vector.elements.len() != 256 {
            return Err(HelixError::InvalidArgument(format!(
                "query_vector must have 256 elements, got {}",
                query_vector.elements.len()
            )));
        }

        // TODO: Implement via tonic gRPC:
        //
        // let request = tonic::Request::new(VectorSearchRequest {
        //     query_vector: query_vector.elements.clone(),
        //     top_k,
        //     min_timestamp,
        //     max_timestamp,
        // });
        // let response = self.client.vector_proximity_search(request).await
        //     .map_err(|e| HelixError::Transport(e.to_string()))?;
        // let inner = response.into_inner();
        // Ok(inner.node_ids.into_iter().zip(inner.distances.into_iter())
        //     .map(|(node_id, distance)| ScoredStateNode { node_id, distance })
        //     .collect())

        let _ = (query_vector, top_k, min_timestamp, max_timestamp);
        Err(HelixError::NotImplemented(
            "vector_proximity_search not yet wired to gRPC".to_string(),
        ))
    }

    /// Cryptographically delete state nodes from the manifold.
    ///
    /// Deletes all nodes for `vault_id` with timestamp < `before_timestamp`.
    /// The `revocation_proof` must be a valid ZK proof of ownership.
    ///
    /// Deletion is forward-private: all historical trajectories through
    /// pruned nodes become mathematically un-navigable.
    ///
    /// # Parameters
    ///
    /// - `vault_id`: Vault ID whose nodes should be pruned
    /// - `before_timestamp`: Delete nodes with timestamp < this value
    /// - `revocation_proof`: ZK proof of ownership (serialized proof bytes)
    ///
    /// # Returns
    ///
    /// Number of nodes pruned.
    pub async fn prune_temporal_node(
        &self,
        vault_id: &[u8; 32],
        before_timestamp: u64,
        revocation_proof: &[u8],
    ) -> Result<u32, HelixError> {
        // TODO: Implement via tonic gRPC:
        //
        // let request = tonic::Request::new(PruneRequest {
        //     vault_id: vault_id.to_vec(),
        //     before_timestamp,
        //     revocation_proof: revocation_proof.to_vec(),
        // });
        // let response = self.client.prune_temporal_node(request).await
        //     .map_err(|e| HelixError::Transport(e.to_string()))?;
        // let inner = response.into_inner();
        // if inner.success {
        //     Ok(inner.pruned_count)
        // } else {
        //     Err(HelixError::Transport(inner.error_message))
        // }

        let _ = (vault_id, before_timestamp, revocation_proof);
        Err(HelixError::NotImplemented(
            "prune_temporal_node not yet wired to gRPC".to_string(),
        ))
    }

    /// Returns the configured gRPC endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

// ── WASM Stub ─────────────────────────────────────────────────────────────────
//
// On wasm32 targets, gRPC/HTTP2 is not available. The WASM build uses a
// JavaScript host bridge instead. The host environment (wasmer.io) is
// responsible for routing HelixDB calls to the actual database.
//
// The WASM stub stores state in WASM linear memory and exposes import/export
// functions for the host to call.

/// WASM linear memory state store (wasm32 target only).
///
/// Stores vault state nodes in WASM linear memory for the host environment
/// to persist to HelixDB. The host calls `wasm_helix_export_nodes()` to
/// retrieve pending nodes and `wasm_helix_import_nodes()` to restore state.
#[cfg(target_arch = "wasm32")]
pub mod wasm_stub {
    use super::{StateNodePayload, Vector256};
    use core::cell::RefCell;
    use alloc::vec::Vec;

    extern crate alloc;

    thread_local! {
        static PENDING_NODES: RefCell<Vec<StateNodePayload>> = RefCell::new(Vec::new());
    }

    /// Queue a state node for host-side HelixDB persistence.
    pub fn queue_state_node(node: StateNodePayload) {
        PENDING_NODES.with(|nodes| {
            nodes.borrow_mut().push(node);
        });
    }

    /// Drain all pending state nodes (called by host to retrieve nodes for persistence).
    pub fn drain_pending_nodes() -> Vec<StateNodePayload> {
        PENDING_NODES.with(|nodes| {
            let mut borrow = nodes.borrow_mut();
            core::mem::take(&mut *borrow)
        })
    }

    /// Count of pending nodes awaiting host-side persistence.
    pub fn pending_node_count() -> usize {
        PENDING_NODES.with(|nodes| nodes.borrow().len())
    }
}
