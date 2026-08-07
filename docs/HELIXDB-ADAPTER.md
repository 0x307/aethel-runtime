---
title: "Aethel-Vault: HelixDB Storage Adapter Specification"
version: "0.1.0-draft"
date: "2026-08-01"
project: "aethel-vault"
---

# HelixDB Storage Adapter Specification

## Table of Contents

1. [HelixDB Architecture](#1-helixdb-architecture)
2. [Schema Design for Encrypted Vault State](#2-schema-design-for-encrypted-vault-state)
3. [gRPC API Surface](#3-grpc-api-surface)
4. [GraphQL API Surface](#4-graphql-api-surface)
5. [mTLS 1.3 Configuration](#5-mtls-13-configuration)
6. [Deployment Topology](#6-deployment-topology)
7. [Client SDK Usage](#7-client-sdk-usage)
8. [Security Considerations](#8-security-considerations)

---

## 1. HelixDB Architecture

### 1.1 Overview

**HelixDB** is a vector-graph hybrid database purpose-built for Aethel's spatial-temporal state trajectory storage. It combines three core capabilities:

```
+------------------------------------------------------------------+
|                    HelixDB Cluster (3+ Nodes)                    |
|                                                                  |
|  ┌─────────────────────────────────────────────────────────┐    |
|  │  Manifold Coordinate System                              │    |
|  │  M = (V, E, T) where V ⊂ R^256, T ∈ R^1               │    |
|  │  Node attribute vectors: v_i ∈ R^256                    │    |
|  │  Polymorphic projection tensor: P_τ(x) = x · R_blind    │    |
|  └─────────────────────────────────────────────────────────┘    |
|                                                                  |
|  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  |
|  │  HNSW Vector     │  │  Graph Engine    │  │  Raft        │  |
|  │  Index (d=256)   │  │  (Temporal       │  │  Consensus   │  |
|  │  Cosine Distance │  │   Trajectories)  │  │  (2N+1)      │  |
|  └──────────────────┘  └──────────────────┘  └──────────────┘  |
|                                                                  |
|  ┌──────────────────────────────────────────────────────────┐   |
|  │  API Surface: HelixQL DSL | gRPC v3 | GraphQL v2026      │   |
|  └──────────────────────────────────────────────────────────┘   |
+------------------------------------------------------------------+
```

### 1.2 Vector-Graph Hybrid Design

HelixDB is not a pure graph database nor a pure vector database. It is a **hybrid** that enables:

1. **Graph traversal**: Temporal trajectory edges between state nodes (`EVOLVED_TO` relationships)
2. **Vector proximity search**: 256-dimensional HNSW approximate nearest-neighbor indexing over M-LWE coefficient vectors
3. **Combined queries**: Filter by graph topology AND vector proximity simultaneously

This hybrid design is essential for Aethel because:
- Identity state evolves over time (graph dimension: temporal trajectories)
- Identity attributes are encoded as polynomial coefficient vectors (vector dimension: proximity search)
- Privacy requires that vector proximity queries reveal relationship validity without exposing exact scalar attribute values

### 1.3 HNSW Vector Index

**HNSW (Hierarchical Navigable Small World)** is the approximate nearest-neighbor algorithm used for vector indexing.

| Parameter | Value | Rationale |
|---|---|---|
| Dimension | 256 | Matches M-LWE ring degree N=256 |
| Distance Metric | Cosine Distance | Normalized R_q coefficients; scale-invariant |
| M (max edges per node) | 32 | Balances index quality and memory |
| ef_construction | 200 | High-quality index construction |
| ef_search | 128 | Accurate search with acceptable latency |
| Index sync mode | Asynchronous | Non-blocking writes |

**Vector normalization**: M-LWE polynomial coefficients (i32 in Z_q) are normalized to Float32 vectors in [-1, 1] for HNSW indexing:

```typescript
// Normalize coefficient c ∈ Z_q to Float32 ∈ [-1, 1]
const normalized = (c > PARAM_Q / 2 ? c - PARAM_Q : c) / (PARAM_Q / 2);
```

### 1.4 Raft Consensus

HelixDB uses **Raft consensus** for distributed state replication across cluster nodes.

| Parameter | Value |
|---|---|
| Minimum cluster size | 3 nodes (2N+1 for fault tolerance) |
| Heartbeat interval | 150ms |
| Election timeout | 1500ms |
| Snapshot threshold | 100,000 events |
| Inter-node security | mTLS 1.3 |

A 3-node cluster tolerates 1 node failure. A 5-node cluster tolerates 2 node failures.

### 1.5 Storage Backend

HelixDB uses **LMDB (Lightning Memory-Mapped Database)** as its storage backend:
- Memory-mapped I/O for high-throughput reads
- ACID transactions
- Copy-on-write B-tree structure
- Zero-copy reads

---

## 2. Schema Design for Encrypted Vault State

### 2.1 HelixQL Native Schema

The HelixDB schema is defined using the HelixQL native DSL (`.hx` schema files):

```
// Node Declarations
N::IdentityHolder {
    holder_pubkey_hash: String,
    created_at_epoch:   Int64,
    active_status:      Boolean
}

N::StateNode {
    node_id:           String,
    temporal_coord_t:  Float64,
    context_id:        String,
    attribute_mask:    Int32,
    h_commit:          Bytes,
    V::attr_vector:    Vector<Float32, 256>
}

N::AttributeAssertion {
    claim_index:       Int32,
    scalar_value:      Int32,
    revocation_tag:    Bytes
}

// Edge Declarations (Non-Linear Temporal & Structural Relationships)
E::EVOLVED_TO {
    time_delta:        Float64,
    geodesic_distance: Float32
}

E::BOUND_TO_HOLDER {
    bound_at_t:        Float64
}

E::CONTAINS_CLAIM {
    slot_index:        Int32
}

// Compiled Query Endpoints
QUERY::GetTemporalTrajectory(start_node_id: String, max_hops: Int32) {
    MATCH (s:StateNode { node_id: $start_node_id })-[e:EVOLVED_TO*1..$max_hops]->(next:StateNode)
    RETURN s, e, next
    ORDER BY next.temporal_coord_t ASC
}

QUERY::VectorProximitySearch(query_vec: Vector<Float32, 256>, k: Int32, min_t: Float64, max_t: Float64) {
    MATCH (n:StateNode)
    WHERE n.temporal_coord_t >= $min_t AND n.temporal_coord_t <= $max_t
    SEARCH n.attr_vector VECTOR_KNN($query_vec, $k)
    RETURN n, _score
}
```

### 2.2 Node Types

**`IdentityHolder`**: Represents an anonymous identity holder. The `holder_pubkey_hash` is a SHA3-256 hash of the holder's ephemeral public projection — not a static public key.

**`StateNode`**: The primary storage unit for identity state. Each node represents a single temporal epoch of an identity's state:
- `node_id`: Unique identifier for this state epoch
- `temporal_coord_t`: Temporal coordinate (Unix timestamp as Float64)
- `context_id`: The context parameter τ used to generate this state
- `attribute_mask`: Bitmask of disclosed attributes
- `h_commit`: SHA3-256 commitment hash of the blinded attribute vector
- `attr_vector`: 256-dimensional Float32 vector for HNSW proximity search

**`AttributeAssertion`**: Stores individual attribute claims linked to a `StateNode`.

### 2.3 Edge Types

**`EVOLVED_TO`**: Temporal evolution edge between consecutive state nodes. The `geodesic_distance` measures the manifold distance between two state projections.

**`BOUND_TO_HOLDER`**: Links a `StateNode` to its `IdentityHolder`.

**`CONTAINS_CLAIM`**: Links a `StateNode` to its `AttributeAssertion` nodes.

### 2.4 Privacy Properties of Stored Data

Attribute vectors stored in HelixDB are **masked with homomorphic lattice noise** to ensure that spatial proximity queries reveal relationship validity without exposing exact scalar attribute values:

```
Stored vector = attr_vector + lattice_noise_mask
```

This means:
- Two vectors from the same identity are close in cosine distance (relationship valid)
- The exact scalar values of attributes cannot be recovered from the stored vector
- Forward-private pruning: deleting a `StateNode` permanently renders all historical sub-graph trajectories mathematically un-navigable

---

## 3. gRPC API Surface

### 3.1 Protocol Buffers Definition

```protobuf
syntax = "proto3";
package aethel.helix.v1;

service HelixManifoldService {
    rpc UpsertStateNode (UpsertStateNodeRequest) returns (UpsertStateNodeResponse);
    rpc TraverseTemporalTrajectory (TraverseTrajectoryRequest) returns (TraverseTrajectoryResponse);
    rpc VectorProximitySearch (VectorSearchRequest) returns (VectorSearchResponse);
    rpc PruneTemporalNode (PruneNodeRequest) returns (PruneNodeResponse);
}

message Vector256 {
    repeated float elements = 1 [packed = true]; // Exactly 256 coefficients
}

message StateNodePayload {
    string node_id = 1;
    double temporal_coord_t = 2;
    string context_id = 3;
    uint32 attribute_mask = 4;
    bytes h_commit = 5;
    Vector256 attr_vector = 6;
}

message UpsertStateNodeRequest {
    string holder_pubkey_hash = 1;
    StateNodePayload node = 2;
    string previous_node_id = 3;
    float geodesic_distance = 4;
}

message VectorSearchRequest {
    Vector256 query_vector = 1;
    uint32 k_nearest = 2;
    double min_temporal_coord = 3;
    double max_temporal_coord = 4;
    uint32 required_attribute_mask = 5;
}

message PruneNodeRequest {
    string target_node_id = 1;
    bytes revocation_proof = 2;
}
```

### 3.2 RPC Methods

**`UpsertStateNode`**: Insert or update a state node in the manifold. Creates an `EVOLVED_TO` edge from `previous_node_id` if provided.

**`TraverseTemporalTrajectory`**: Traverse the temporal trajectory graph from a starting node, following `EVOLVED_TO` edges up to `max_hops` depth.

**`VectorProximitySearch`**: Execute a k-nearest-neighbor search over the HNSW vector index, filtered by temporal coordinate range and attribute mask.

**`PruneTemporalNode`**: Cryptographically delete a state node. The `revocation_proof` must be a valid ZK proof of ownership. Deletion is forward-private: all historical trajectories through this node become un-navigable.

### 3.3 Rust gRPC Client (tonic)

The Rust client SDK uses `tonic` for gRPC transport:

```rust
use tonic::transport::Channel;
use aethel_helix::helix_manifold_service_client::HelixManifoldServiceClient;

pub struct HelixDbAdapter {
    client: HelixManifoldServiceClient<Channel>,
}

impl HelixDbAdapter {
    pub async fn new(endpoint: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let channel = Channel::from_shared(endpoint.to_string())?
            .tls_config(tls_config)?
            .connect()
            .await?;
        Ok(Self {
            client: HelixManifoldServiceClient::new(channel),
        })
    }

    pub async fn upsert_state_node(
        &mut self,
        holder_hash: &str,
        node: StateNodePayload,
        previous_node_id: Option<&str>,
        geodesic_distance: f32,
    ) -> Result<UpsertStateNodeResponse, tonic::Status> {
        let request = tonic::Request::new(UpsertStateNodeRequest {
            holder_pubkey_hash: holder_hash.to_string(),
            node: Some(node),
            previous_node_id: previous_node_id.unwrap_or("").to_string(),
            geodesic_distance,
        });
        self.client.upsert_state_node(request).await
            .map(|r| r.into_inner())
    }

    pub async fn vector_proximity_search(
        &mut self,
        query_vector: Vec<f32>,
        k_nearest: u32,
        min_t: f64,
        max_t: f64,
        attribute_mask: u32,
    ) -> Result<VectorSearchResponse, tonic::Status> {
        let request = tonic::Request::new(VectorSearchRequest {
            query_vector: Some(Vector256 { elements: query_vector }),
            k_nearest,
            min_temporal_coord: min_t,
            max_temporal_coord: max_t,
            required_attribute_mask: attribute_mask,
        });
        self.client.vector_proximity_search(request).await
            .map(|r| r.into_inner())
    }
}
```

---

## 4. GraphQL API Surface

### 4.1 GraphQL Schema

```graphql
scalar Float256Vector
scalar Bytes32
scalar DateTime64

type StateNode {
    nodeId: ID!
    temporalCoordT: Float!
    contextId: String!
    attributeMask: Int!
    hCommit: Bytes32!
    attrVector: Float256Vector!
    parentTrajectory: [StateNode!]!
    childTrajectory: [StateNode!]!
}

type Query {
    getStateNode(nodeId: ID!): StateNode
    traverseTrajectory(startNodeId: ID!, maxDepth: Int = 5): [StateNode!]!
    searchAttributeProximity(queryVector: Float256Vector!, k: Int = 10, minTime: Float, maxTime: Float): [ScoredStateNode!]!
}

type Mutation {
    upsertStateNode(holderHash: String!, node: StateNodeInput!, previousNodeId: String): StateNodePayloadResult!
    pruneTemporalEpoch(nodeId: ID!, epochBlindingRevocation: Bytes32!): Boolean!
}
```

### 4.2 Custom Scalars

**`Float256Vector`**: A 256-element Float32 array, serialized as a JSON array of numbers.

**`Bytes32`**: A 32-byte value, serialized as a hex-encoded string (64 hex characters).

**`DateTime64`**: A 64-bit Unix timestamp (milliseconds), serialized as a JSON number.

### 4.3 Example Queries

**Get a state node:**
```graphql
query GetNode($nodeId: ID!) {
    getStateNode(nodeId: $nodeId) {
        nodeId
        temporalCoordT
        contextId
        attributeMask
        hCommit
    }
}
```

**Traverse temporal trajectory:**
```graphql
query Trajectory($startId: ID!) {
    traverseTrajectory(startNodeId: $startId, maxDepth: 10) {
        nodeId
        temporalCoordT
        attributeMask
    }
}
```

**Vector proximity search:**
```graphql
query ProximitySearch($vec: Float256Vector!, $k: Int!) {
    searchAttributeProximity(queryVector: $vec, k: $k, minTime: 0.0, maxTime: 9999999999.0) {
        node { nodeId temporalCoordT }
        score
    }
}
```

---

## 5. mTLS 1.3 Configuration

### 5.1 Overview

All inter-node communication and client-to-cluster communication uses **mutual TLS 1.3 (mTLS)**. Both client and server present certificates, ensuring:
- **Server authentication**: Client verifies the HelixDB cluster identity
- **Client authentication**: Cluster verifies the client identity
- **Forward secrecy**: TLS 1.3 ephemeral key exchange (X25519 or ML-KEM in post-quantum mode)
- **Encryption**: All data in transit is encrypted

### 5.2 Certificate Hierarchy

```
Root CA (Aethel PKI)
├── Intermediate CA (HelixDB Cluster)
│   ├── Node Certificate (helix-node-0.internal)
│   ├── Node Certificate (helix-node-1.internal)
│   └── Node Certificate (helix-node-2.internal)
└── Intermediate CA (Aethel Gateway)
    ├── Gateway Certificate (gateway.aethel.network)
    └── Client Certificate (aethel-vault-client)
```

### 5.3 TLS Configuration (Rust/tonic)

```rust
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

fn build_tls_config(
    ca_cert_pem: &[u8],
    client_cert_pem: &[u8],
    client_key_pem: &[u8],
) -> ClientTlsConfig {
    let ca_cert = Certificate::from_pem(ca_cert_pem);
    let client_identity = Identity::from_pem(client_cert_pem, client_key_pem);

    ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(client_identity)
        .domain_name("helix.aethel.network")
}
```

### 5.4 TLS 1.3 Cipher Suites

Permitted cipher suites (TLS 1.3 only):
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

TLS 1.2 and below are **explicitly disabled**.

### 5.5 Certificate Rotation

Certificates are rotated on a 90-day cycle using automated ACME or internal PKI tooling. The cluster supports zero-downtime certificate rotation via:
1. New certificate loaded into secondary slot
2. Gradual traffic migration to new certificate
3. Old certificate revoked after all connections drain

---

## 6. Deployment Topology

### 6.1 Cluster Sizing

| Deployment | Nodes | Fault Tolerance | Use Case |
|---|---|---|---|
| Development | 1 | None | Local testing |
| Staging | 3 | 1 node failure | Integration testing |
| Production (small) | 3 | 1 node failure | Low-traffic deployments |
| Production (standard) | 5 | 2 node failures | Standard production |
| Production (high-availability) | 7 | 3 node failures | Critical infrastructure |

### 6.2 Port Allocation

| Service | Port | Protocol |
|---|---|---|
| Envoy Proxy | 443 | HTTPS/gRPC (mTLS) |
| Aethel Gateway HTTP | 8080 | HTTP (internal) |
| Aethel Gateway gRPC | 9090 | gRPC (internal) |
| HelixDB Engine | 7070 | gRPC (internal) |
| HelixDB Raft | 7071 | TCP (mTLS) |
| HelixDB Gossip | 7072 | UDP |
| Prometheus | 9100 | HTTP (metrics) |

### 6.3 Docker Compose (Development)

```yaml
version: '3.8'
services:
  helix-node-0:
    image: helixdb:latest
    ports:
      - "7070:7070"
      - "7071:7071"
      - "7072:7072"
    environment:
      - HELIX_NODE_ID=0
      - HELIX_CLUSTER_PEERS=helix-node-1:7071,helix-node-2:7071
      - HELIX_MTLS_CERT=/certs/node-0.crt
      - HELIX_MTLS_KEY=/certs/node-0.key
      - HELIX_MTLS_CA=/certs/ca.crt
    volumes:
      - helix-data-0:/data
      - ./certs:/certs:ro

  helix-node-1:
    image: helixdb:latest
    environment:
      - HELIX_NODE_ID=1
      - HELIX_CLUSTER_PEERS=helix-node-0:7071,helix-node-2:7071
    volumes:
      - helix-data-1:/data
      - ./certs:/certs:ro

  helix-node-2:
    image: helixdb:latest
    environment:
      - HELIX_NODE_ID=2
      - HELIX_CLUSTER_PEERS=helix-node-0:7071,helix-node-1:7071
    volumes:
      - helix-data-2:/data
      - ./certs:/certs:ro

  aethel-gateway:
    image: aethel-gateway:latest
    ports:
      - "8080:8080"
      - "9090:9090"
    environment:
      - HELIX_ENDPOINT=helix-node-0:7070
    depends_on:
      - helix-node-0

  envoy:
    image: envoyproxy/envoy:latest
    ports:
      - "443:443"
    volumes:
      - ./envoy.yaml:/etc/envoy/envoy.yaml:ro
      - ./certs:/certs:ro
    depends_on:
      - aethel-gateway

volumes:
  helix-data-0:
  helix-data-1:
  helix-data-2:
```

### 6.4 systemd Service (Production)

```ini
[Unit]
Description=HelixDB Node
After=network.target
Requires=network.target

[Service]
Type=simple
User=helixdb
Group=helixdb
ExecStart=/usr/local/bin/helixdb \
    --node-id=${HELIX_NODE_ID} \
    --data-dir=/var/lib/helixdb \
    --grpc-port=7070 \
    --raft-port=7071 \
    --gossip-port=7072 \
    --peers=${HELIX_CLUSTER_PEERS} \
    --tls-cert=/etc/helixdb/certs/node.crt \
    --tls-key=/etc/helixdb/certs/node.key \
    --tls-ca=/etc/helixdb/certs/ca.crt
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### 6.5 Replication Configuration

```
Raft Replication:
- Write quorum: (N/2) + 1 nodes must acknowledge before commit
- Read consistency: Linearizable reads require leader confirmation
- Log compaction: Snapshot at 100,000 events; old log entries pruned
- Snapshot transfer: Chunked binary transfer over mTLS gRPC stream
```

---

## 7. Client SDK Usage

### 7.1 Rust Client SDK

The Rust client SDK (`aethel-vault/src/storage/helixdb.rs`) provides a high-level interface to HelixDB:

```rust
use aethel_vault::storage::helixdb::HelixDbAdapter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize adapter with mTLS configuration
    let adapter = HelixDbAdapter::new(
        "https://helix.aethel.network:443",
        &ca_cert_pem,
        &client_cert_pem,
        &client_key_pem,
    ).await?;

    // Upsert a state node
    let node = StateNodePayload {
        node_id: "node-epoch-1000".to_string(),
        temporal_coord_t: 1000.0,
        context_id: hex::encode(&context_tag),
        attribute_mask: 0b00000011, // Attributes 0 and 1 disclosed
        h_commit: commitment_hash.to_vec(),
        attr_vector: Some(Vector256 { elements: normalized_coeffs }),
    };

    adapter.upsert_state_node(
        &holder_hash,
        node,
        None, // No previous node (first epoch)
        0.0,  // Geodesic distance
    ).await?;

    // Vector proximity search
    let results = adapter.vector_proximity_search(
        query_vector,
        10,    // k=10 nearest neighbors
        0.0,   // min temporal coordinate
        f64::MAX, // max temporal coordinate
        0b00000001, // Required attribute mask
    ).await?;

    Ok(())
}
```

### 7.2 TypeScript Client SDK

The TypeScript client SDK (`aethel-vault/src/sdk/client.ts`) provides browser/Node.js access to HelixDB:

> **Note:** The TypeScript SDK for HelixDB integration is shared between `aethel-id` and `aethel-vault`. The canonical implementation lives in `aethel-id/src/sdk/client.ts`. The `aethel-vault/src/sdk/client.ts` file provides a vault-specific stub that re-exports and extends the shared SDK with vault-specific functionality.

```typescript
import { AethelClientSDK } from '@aethel/sdk';

const sdk = new AethelClientSDK({
    nodeEndpoint: 'https://helix.aethel.network'
});

// Map M-LWE coefficients to 256-dim Float32 vector for HNSW indexing
const vector = sdk.mapCoeffsToVector256(coefficients);

// Create state node ingestion payload
const payload = await sdk.createIngestionPayload({
    holderHash: holderPubkeyHash,
    contextId: contextTag,
    attributeMask: disclosureMask,
    coefficients: coefficients,
});

// Verify a SAAP proof transcript
const valid = await sdk.verifySaapProof({
    proof: saapProof,
    disclosedAttributes: attributes,
    contextTag: tau,
});
```

### 7.3 Key SDK Methods

| Method | Description |
|---|---|
| `mapCoeffsToVector256(coeffs)` | Normalize M-LWE i32 coefficients to Float32 [-1,1] for HNSW |
| `createIngestionPayload(params)` | Build a HelixDB `UpsertStateNodeRequest` payload |
| `verifySaapProof(params)` | Verify a SAAP proof transcript against disclosed attributes |

---

## 8. Security Considerations

### 8.1 Cryptographic Node Deletion

Nodes containing transient secrets MUST be stored encrypted under ephemeral storage keys. Node deletion MUST be executed by cryptographically zeroizing the local node key:

```
Delete(node_id):
1. Retrieve ephemeral storage key K_node for node_id
2. Overwrite all data blocks for node_id with zeros
3. Zeroize K_node from key store
4. Remove node_id from graph index
5. Remove node_id from HNSW vector index
```

After deletion, the node's data is cryptographically irrecoverable, and all historical sub-graph trajectories through this node become mathematically un-navigable.

### 8.2 Sub-Graph Isolation

Query execution over localized sub-graphs `G_sub(t)` MUST restrict pointer traversal to explicit topological edges. Queries MUST NOT:
- Follow edges outside the requested temporal range
- Access nodes not reachable from the query root via declared edge types
- Return vector similarity scores that could reveal exact attribute values

### 8.3 Manifold Trajectory Reconstruction Attack

Implementations MUST break temporal continuity by applying fresh, randomized vector projection transforms (Polymorphic Projections) to all node embeddings written to the storage manifold across epoch shifts:

```
For each new epoch τ:
    stored_vector = attr_vector · R_blind(τ)
    where R_blind(τ) is a fresh random rotation matrix derived from τ
```

This ensures that even if an adversary observes multiple stored vectors from the same identity, they cannot reconstruct the temporal trajectory without knowledge of the rotation matrices.

### 8.4 Vector Proximity Snooping

Attribute vector commitments stored in HelixDB MUST be masked with homomorphic lattice noise to ensure that spatial proximity queries reveal relationship validity without exposing exact scalar attribute values.

### 8.5 Forward Private Graph Pruning

Implementations using temporal graph manifolds MUST support forward-private pruning, wherein clearing a past temporal epoch node `t_k` permanently renders all historical sub-graph trajectories mathematically un-navigable.

### 8.6 Helper Data Non-Leakage

The public helper data string `W_sketch` derived during BCH enrollment reveals strictly at most `n_bch - k_bch` bits of information about the raw SRAM power-up state. HelixDB storage of helper data MUST be encrypted at rest.

---

*See also:*
- [`OVERVIEW.md`](./OVERVIEW.md) — High-level architecture overview
- [`TFHE-VAULT-SPEC.md`](./TFHE-VAULT-SPEC.md) — TFHE vault technical specification
- [`src/storage/helixdb.rs`](../src/storage/helixdb.rs) — HelixDB adapter source code
- [`src/sdk/client.ts`](../src/sdk/client.ts) — TypeScript client SDK
