//! Per-category 3-hop path pool.
//!
//! Maintains a set of onion paths grouped by category (e.g. standard /
//! file-download). Each path is a fixed sequence of service nodes with the
//! first node — the **guard** — being the node the client actually connects
//! to. Paths are rebuilt when a strike threshold is exceeded.
//!
//! This is a pure in-memory structure; the live networking happens in
//! `OnionRequestRouter`.
//!
//! ## Invariants
//!
//! * Every path has exactly three distinct service nodes (`PATH_HOPS = 3`).
//! * Guards across paths are disjoint — no two active paths share a guard.
//! * No two hops within a single path are the same snode.

use std::collections::HashSet;

use crate::network::key_types::Ed25519Pubkey;
use crate::network::service_node::ServiceNode;
use crate::network::snode_pool::SnodePool;

/// Standard 3-hop onion routing: guard → middle → exit.
pub const PATH_HOPS: usize = 3;

/// Category for an onion path. The library keeps separate path pools for each
/// category because the native clients rotate them independently (e.g. file
/// downloads are routed on their own pool so a slow transfer does not blow
/// rotation budget for chat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathCategory {
    /// Paths for ordinary snode RPCs (store / retrieve / config).
    Standard,
    /// Paths reserved for file uploads / downloads.
    File,
}

/// A single 3-hop path.
#[derive(Debug, Clone)]
pub struct OnionPath {
    /// The hops, ordered from guard (index 0) to exit (index 2).
    pub hops: [ServiceNode; PATH_HOPS],
    /// Number of failures recorded against this path. When this reaches the
    /// configured strike threshold, [`PathManager::rebuild_path`] should be
    /// called to replace it.
    pub strikes: u8,
}

impl OnionPath {
    /// Returns true when `node` appears anywhere in this path.
    pub fn contains(&self, node: &Ed25519Pubkey) -> bool {
        self.hops.iter().any(|n| &n.ed25519_pubkey == node)
    }

    /// Returns the guard (first-hop) snode.
    pub fn guard(&self) -> &ServiceNode {
        &self.hops[0]
    }
}

/// Error returned when path building fails.
#[derive(Debug, thiserror::Error)]
pub enum PathManagerError {
    /// Snode pool contains fewer nodes than required to build a path.
    #[error("pool too small: have {have}, need {need}")]
    PoolTooSmall {
        /// Nodes currently in the pool.
        have: usize,
        /// Minimum required for the requested build.
        need: usize,
    },
    /// Unknown category requested.
    #[error("unknown category")]
    UnknownCategory,
}

/// Configuration for [`PathManager`].
#[derive(Debug, Clone)]
pub struct PathManagerConfig {
    /// Target number of live paths per category.
    pub target_paths_per_category: u8,
    /// Number of failures before a path is considered dead.
    pub path_strike_threshold: u8,
}

impl Default for PathManagerConfig {
    fn default() -> Self {
        Self {
            target_paths_per_category: 2,
            path_strike_threshold: 3,
        }
    }
}

/// Per-category 3-hop onion-path pool.
pub struct PathManager {
    config: PathManagerConfig,
    standard_paths: Vec<OnionPath>,
    file_paths: Vec<OnionPath>,
}

impl PathManager {
    /// Creates an empty manager.
    pub fn new(config: PathManagerConfig) -> Self {
        Self {
            config,
            standard_paths: Vec::new(),
            file_paths: Vec::new(),
        }
    }

    /// Returns the number of live paths in a category.
    pub fn path_count(&self, category: PathCategory) -> usize {
        self.paths_for(category).len()
    }

    /// Returns a snapshot of the live paths in a category.
    pub fn paths(&self, category: PathCategory) -> Vec<OnionPath> {
        self.paths_for(category).clone()
    }

    /// Returns an arbitrary live path for the category, if any.
    pub fn pick_path(&self, category: PathCategory) -> Option<OnionPath> {
        use rand::prelude::IndexedRandom;
        let paths = self.paths_for(category);
        let mut rng = rand::rng();
        paths.choose(&mut rng).cloned()
    }

    /// Records a failure against the guard of a given path. When the path's
    /// strike count reaches the threshold it is removed and will need to be
    /// rebuilt.
    pub fn record_failure(&mut self, category: PathCategory, guard: &Ed25519Pubkey) {
        let threshold = self.config.path_strike_threshold;
        let list = self.paths_for_mut(category);
        list.retain_mut(|p| {
            if &p.guard().ed25519_pubkey == guard {
                p.strikes += 1;
                p.strikes < threshold
            } else {
                true
            }
        });
    }

    /// Drops every path that has at least one failure. Useful when the
    /// caller knows something has changed globally (e.g. pool refresh).
    pub fn drop_strike_paths(&mut self, category: PathCategory) {
        self.paths_for_mut(category).retain(|p| p.strikes == 0);
    }

    /// Drops every live path in the category.
    pub fn clear(&mut self, category: PathCategory) {
        self.paths_for_mut(category).clear();
    }

    /// Tops up the pool so it has at least `target_paths_per_category` paths,
    /// building new ones from the snode pool. New guards are chosen to be
    /// disjoint from already-used guards.
    pub fn build_up_to_target(
        &mut self,
        category: PathCategory,
        pool: &SnodePool,
    ) -> Result<usize, PathManagerError> {
        let target = self.config.target_paths_per_category as usize;
        let mut built = 0usize;
        while self.path_count(category) < target {
            match self.build_one(category, pool) {
                Ok(_) => built += 1,
                Err(PathManagerError::PoolTooSmall { .. }) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(built)
    }

    /// Builds a single path for the category using the given snode pool,
    /// avoiding any guards currently in use by other live paths in this
    /// category.
    pub fn build_one(
        &mut self,
        category: PathCategory,
        pool: &SnodePool,
    ) -> Result<OnionPath, PathManagerError> {
        let used_guards: HashSet<Ed25519Pubkey> = self
            .paths_for(category)
            .iter()
            .map(|p| p.guard().ed25519_pubkey)
            .collect();

        // Pull enough unused nodes to guarantee we can pick three distinct
        // non-guard snodes even if the first selection collides.
        let exclude: Vec<ServiceNode> = self
            .paths_for(category)
            .iter()
            .flat_map(|p| p.hops.iter().cloned())
            .collect();

        let candidates = pool.get_unused_nodes(PATH_HOPS + used_guards.len(), &exclude);
        if candidates.len() < PATH_HOPS {
            return Err(PathManagerError::PoolTooSmall {
                have: candidates.len() + exclude.len(),
                need: PATH_HOPS * (used_guards.len() + 1),
            });
        }

        // Pick the first three distinct nodes, skipping any whose pubkey is
        // already a guard elsewhere (for the guard slot).
        let mut iter = candidates.into_iter();
        let mut hops: Vec<ServiceNode> = Vec::with_capacity(PATH_HOPS);
        for node in iter.by_ref() {
            // Guard (index 0) must be a fresh guard.
            if hops.is_empty() && used_guards.contains(&node.ed25519_pubkey) {
                continue;
            }
            // No duplicate nodes within the path.
            if hops.iter().any(|n| n.ed25519_pubkey == node.ed25519_pubkey) {
                continue;
            }
            hops.push(node);
            if hops.len() == PATH_HOPS {
                break;
            }
        }
        if hops.len() < PATH_HOPS {
            return Err(PathManagerError::PoolTooSmall {
                have: hops.len(),
                need: PATH_HOPS,
            });
        }

        let path = OnionPath {
            hops: [hops[0].clone(), hops[1].clone(), hops[2].clone()],
            strikes: 0,
        };
        self.paths_for_mut(category).push(path.clone());
        Ok(path)
    }

    /// Drops the path whose guard matches `guard` and rebuilds a replacement
    /// immediately.
    pub fn rebuild_path(
        &mut self,
        category: PathCategory,
        guard: &Ed25519Pubkey,
        pool: &SnodePool,
    ) -> Result<OnionPath, PathManagerError> {
        self.paths_for_mut(category)
            .retain(|p| &p.guard().ed25519_pubkey != guard);
        self.build_one(category, pool)
    }

    fn paths_for(&self, category: PathCategory) -> &Vec<OnionPath> {
        match category {
            PathCategory::Standard => &self.standard_paths,
            PathCategory::File => &self.file_paths,
        }
    }

    fn paths_for_mut(&mut self, category: PathCategory) -> &mut Vec<OnionPath> {
        match category {
            PathCategory::Standard => &mut self.standard_paths,
            PathCategory::File => &mut self.file_paths,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::key_types::Ed25519Pubkey;
    use crate::network::snode_pool::SnodePoolConfig;
    use crate::network::swarm::INVALID_SWARM_ID;

    fn make_node(id: u8) -> ServiceNode {
        let mut pk = [0u8; 32];
        pk[0] = id;
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey(pk),
            ip: [10, 0, 0, id],
            https_port: 443,
            omq_port: 22000,
            storage_server_version: [2, 11, 0],
            swarm_id: INVALID_SWARM_ID,
            requested_unlock_height: 0,
        }
    }

    fn pool_with(n: usize) -> SnodePool {
        let mut pool = SnodePool::new(SnodePoolConfig::default());
        let nodes: Vec<ServiceNode> = (1..=n as u8).map(make_node).collect();
        pool.add_nodes(nodes);
        pool
    }

    #[test]
    fn test_builds_three_hop_path_from_disjoint_nodes() {
        let mut mgr = PathManager::new(PathManagerConfig::default());
        let pool = pool_with(6);
        let p = mgr.build_one(PathCategory::Standard, &pool).unwrap();
        assert_eq!(p.hops.len(), 3);
        // No duplicate hops within a path.
        assert_ne!(p.hops[0].ed25519_pubkey, p.hops[1].ed25519_pubkey);
        assert_ne!(p.hops[1].ed25519_pubkey, p.hops[2].ed25519_pubkey);
        assert_ne!(p.hops[0].ed25519_pubkey, p.hops[2].ed25519_pubkey);
    }

    #[test]
    fn test_pool_too_small_errors() {
        let mut mgr = PathManager::new(PathManagerConfig::default());
        let pool = pool_with(2);
        assert!(
            matches!(
                mgr.build_one(PathCategory::Standard, &pool),
                Err(PathManagerError::PoolTooSmall { .. })
            )
        );
    }

    #[test]
    fn test_build_up_to_target_makes_disjoint_guards() {
        let mut mgr = PathManager::new(PathManagerConfig {
            target_paths_per_category: 2,
            path_strike_threshold: 3,
        });
        let pool = pool_with(20);
        let n = mgr.build_up_to_target(PathCategory::Standard, &pool).unwrap();
        assert_eq!(n, 2);
        assert_eq!(mgr.path_count(PathCategory::Standard), 2);

        let paths = mgr.paths(PathCategory::Standard);
        assert_ne!(paths[0].guard().ed25519_pubkey, paths[1].guard().ed25519_pubkey);
    }

    #[test]
    fn test_standard_and_file_are_independent() {
        let mut mgr = PathManager::new(PathManagerConfig::default());
        let pool = pool_with(20);
        mgr.build_up_to_target(PathCategory::Standard, &pool).unwrap();
        mgr.build_up_to_target(PathCategory::File, &pool).unwrap();
        assert!(mgr.path_count(PathCategory::Standard) > 0);
        assert!(mgr.path_count(PathCategory::File) > 0);
    }

    #[test]
    fn test_record_failure_retires_after_threshold() {
        let mut mgr = PathManager::new(PathManagerConfig {
            target_paths_per_category: 1,
            path_strike_threshold: 3,
        });
        let pool = pool_with(20);
        mgr.build_up_to_target(PathCategory::Standard, &pool).unwrap();

        let guard = mgr.paths(PathCategory::Standard)[0]
            .guard()
            .ed25519_pubkey;

        mgr.record_failure(PathCategory::Standard, &guard);
        assert_eq!(mgr.path_count(PathCategory::Standard), 1);
        mgr.record_failure(PathCategory::Standard, &guard);
        assert_eq!(mgr.path_count(PathCategory::Standard), 1);
        mgr.record_failure(PathCategory::Standard, &guard);
        assert_eq!(mgr.path_count(PathCategory::Standard), 0);
    }

    #[test]
    fn test_rebuild_path_replaces_guard() {
        let mut mgr = PathManager::new(PathManagerConfig {
            target_paths_per_category: 1,
            path_strike_threshold: 3,
        });
        let pool = pool_with(20);
        mgr.build_up_to_target(PathCategory::Standard, &pool).unwrap();
        let old_guard = mgr.paths(PathCategory::Standard)[0]
            .guard()
            .ed25519_pubkey;

        let new_path = mgr
            .rebuild_path(PathCategory::Standard, &old_guard, &pool)
            .unwrap();
        assert_ne!(new_path.guard().ed25519_pubkey, old_guard);
        assert_eq!(mgr.path_count(PathCategory::Standard), 1);
    }

    #[test]
    fn test_clear_removes_all() {
        let mut mgr = PathManager::new(PathManagerConfig::default());
        let pool = pool_with(20);
        mgr.build_up_to_target(PathCategory::Standard, &pool).unwrap();
        assert!(mgr.path_count(PathCategory::Standard) > 0);
        mgr.clear(PathCategory::Standard);
        assert_eq!(mgr.path_count(PathCategory::Standard), 0);
    }
}
