pub mod helpers;

#[cfg(test)]
mod fast_zk_tests {
    use super::helpers::{build_groth_script, build_stark_script, execute_zk_script};
    use crate::caches::Cache;
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;

    #[test]
    fn test_groth16_fast() {
        let script = build_groth_script();
        let cache = Cache::new(0);
        let reused_values = SigHashReusedValuesUnsync::new();
        execute_zk_script(&script, &cache, &reused_values).unwrap();
    }

    #[test]
    fn test_r0_succinct_fast() {
        let script = build_stark_script();
        let cache = Cache::new(0);
        let reused_values = SigHashReusedValuesUnsync::new();
        execute_zk_script(&script, &cache, &reused_values).unwrap();
    }
}
