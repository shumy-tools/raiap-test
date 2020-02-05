use std::collections::BTreeMap;

use serde::{Serialize, Deserialize};
use ed25519_dalek::{Keypair, PublicKey, Signature};

use sha2::{Sha256, Digest};
use base64::encode;

use crate::structs::identity::TLGroup;
use crate::structs::{Result, OType};

pub fn asi(key: &PublicKey, sig: &Signature) -> String {
  let mut hasher = Sha256::new();
  hasher.input(key.as_bytes());
  hasher.input(sig.to_bytes().as_ref());
  let result = hasher.result();
  
  encode(&result)
}

//-----------------------------------------------------------------------------------------------------------
// Stream (also represents stream genesis)
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Stream {
  pub asi: String,
  pub groups: BTreeMap<String, TLGroup>,
  pub genesis: Record,
  pub sig: Signature,
  
  pub blocks: Vec<StreamBlock>
}

impl Stream {
  pub fn new(keypair: &Keypair, udi: &str, r: &str, groups: &[TLGroup], genesis: Record) -> Self {
    let mut g_map = BTreeMap::<String, TLGroup>::new();
    for gr in groups.into_iter() {
      g_map.insert(gr.commit.clone(), gr.clone());
    }

    let sig_data = Self::asi_data(udi, r);
    let sig = keypair.sign(&sig_data);
    let asi = asi(&keypair.public, &sig);

    let sig_data = Self::data(&asi, &g_map, &genesis);
    let sig = keypair.sign(&sig_data);

    Self { asi, groups: g_map, genesis, sig, blocks: Vec::new() }
  }

  pub fn prev(&self) -> &Signature {
    match self.blocks.last() {
      None => &self.sig,
      Some(bl) => &bl.sig
    }
  }

  pub fn save(&mut self, block: StreamBlock) -> Result<()> {
    let sig = self.prev();
    if block.prev != *sig {
      return Err("Invalid stream chain!".into())
    }

    self.blocks.push(block);
    Ok(())
  }

  pub fn check_asi(&self, udi: &str, r: &str, key: &PublicKey, sig: &Signature) -> bool {
    let asi = asi(key, sig);
    if asi != self.asi {
      return false
    }

    let sig_data = Self::asi_data(udi, r);
    key.verify(&sig_data, sig).is_ok()
  }

  pub fn verify_chain(&self, key: &PublicKey) -> Result<()> {
    if !self.verify(key) {
      return Err("Invalid genesis signature!".into())
    }

    for bl in self.blocks.iter() {
      if !bl.verify(key) {
        return Err("Invalid block signature!".into())
      }
    }

    Ok(())
  }

  pub fn verify(&self, key: &PublicKey) -> bool {
    let sig_data = Self::data(&self.asi, &self.groups, &self.genesis);
    key.verify(&sig_data, &self.sig).is_ok()
  }

  fn data(asi: &str, groups: &BTreeMap<String, TLGroup>, genesis: &Record) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    // These unwrap() should never fail, or it's a serious code bug!
    data.extend(bincode::serialize(asi).unwrap());
    data.extend(bincode::serialize(groups).unwrap());
    data.extend(bincode::serialize(genesis).unwrap());
    
    data
  }

  fn asi_data(udi: &str, r: &str) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    // These unwrap() should never fail, or it's a serious code bug!
    data.extend(bincode::serialize(udi).unwrap());
    data.extend(bincode::serialize(r).unwrap());
    
    data
  }
}

//-----------------------------------------------------------------------------------------------------------
// All other stream structures
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Record {
  pub oper: OType,
  pub info: Vec<u8>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StreamBlock {
  pub record: Record,
  pub prev: Signature,
  pub sig: Signature
}

impl StreamBlock {
  pub fn new(keypair: &Keypair, record: Record, prev: &Signature) -> Self {
    let sig_data = Self::data(&record, &prev);
    let sig = keypair.sign(&sig_data);

    Self { record, prev: prev.clone(), sig }
  }

  pub fn verify(&self, key: &PublicKey) -> bool {
    let sig_data = Self::data(&self.record, &self.prev);
    key.verify(&sig_data, &self.sig).is_ok()
  }

  fn data(record: &Record, prev: &Signature) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    // These unwrap() should never fail, or it's a serious code bug!    
    data.extend(bincode::serialize(record).unwrap());
    data.extend(bincode::serialize(prev).unwrap());
    
    data
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::structs::anchor::*;

  use rand::rngs::OsRng;
  use ed25519_dalek::Keypair;

  #[test]
  fn create_stream() {
    // achor data
    let udi = "udi-random";
    let r = "r-random";

    // achor
    let mut csprng = OsRng{};
    let profile_keypair: Keypair = Keypair::generate(&mut csprng);
    let anchor = Anchor::new(&profile_keypair, udi, r, 0);

    // create stream
    let genesis = Record { oper: OType::SET, info: b"Not important!".to_vec() };
    let mut stream = Stream::new(&profile_keypair, udi, r, &vec![], genesis);
  
    // add block to stream
    let record = Record { oper: OType::SET, info: b"New info!".to_vec() };
    let block = StreamBlock::new(&profile_keypair, record, &stream.sig);
    stream.save(block).unwrap();
    stream.verify_chain(&profile_keypair.public).unwrap();

    // check if ASI is connected to the anchor AL ?
    let al_sig = anchor.al_signature(&profile_keypair, udi);
    assert!(stream.check_asi(udi, r, &profile_keypair.public, &al_sig));
  }
}