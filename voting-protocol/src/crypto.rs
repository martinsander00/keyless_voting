use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nullifier([u8; 32]);

pub trait KeylessCircuit {
    fn create_proof(&self, pepper: &[u8], nullifier: &Nullifier) -> Vec<u8>;
    fn verify_proof(&self, proof: &[u8], nullifier: &Nullifier) -> bool;
}

impl Nullifier {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}
