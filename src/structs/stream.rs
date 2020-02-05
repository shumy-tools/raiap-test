use std::collections::BTreeMap;

use serde::{Serialize, Deserialize};
use ed25519_dalek::{Keypair, PublicKey, Signature};

use sha2::{Sha256, Digest};
use base64::encode;

use crate::structs::identity::*;
use crate::structs::{Result, OType};

pub fn asi(key: &PublicKey, sig: &Signature) -> String {
  let mut hasher = Sha256::new();
  hasher.input(key.as_bytes());
  hasher.input(sig.to_bytes().as_ref());
  let result = hasher.result();
  
  encode(&result)
}

//-----------------------------------------------------------------------------------------------------------
// Extended Renew block
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExtRenew {
  renew: Renew,
  key: PublicKey
}

//-----------------------------------------------------------------------------------------------------------
// Stream (also represents stream genesis)
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Stream {
  pub asi: String,
  pub groups: BTreeMap<String, TLGroup>,
  pub genesis: Record,
  pub renew: Option<ExtRenew>,
  pub sig: Signature,
  
  pub blocks: Vec<StreamBlock>
}

impl Stream {
  pub fn new(keypair: &Keypair, udi: &str, r: &str, groups: &[TLGroup], genesis: Record, renew: Option<ExtRenew>) -> Self {
    let mut g_map = BTreeMap::<String, TLGroup>::new();
    for gr in groups.into_iter() {
      g_map.insert(gr.commit.clone(), gr.clone());
    }

    let sig_data = Self::asi_data(udi, r);
    let sig = keypair.sign(&sig_data);
    let asi = asi(&keypair.public, &sig);

    let sig_data = Self::data(&asi, &g_map, &genesis, &renew);
    let sig = keypair.sign(&sig_data);

    Self { asi, groups: g_map, genesis, sig, blocks: Vec::new(), renew }
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

  pub fn verify_stream(&self, key: &PublicKey) -> Result<()> {
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
    let sig_data = Self::data(&self.asi, &self.groups, &self.genesis, &self.renew);
    key.verify(&sig_data, &self.sig).is_ok()
  }

  fn data(asi: &str, groups: &BTreeMap<String, TLGroup>, genesis: &Record, renew: &Option<ExtRenew>) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    // These unwrap() should never fail, or it's a serious code bug!
    data.extend(bincode::serialize(asi).unwrap());
    data.extend(bincode::serialize(groups).unwrap());
    data.extend(bincode::serialize(genesis).unwrap());
    data.extend(bincode::serialize(renew).unwrap());
    
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

//-----------------------------------------------------------------------------------------------------------
// Stream Chain
//-----------------------------------------------------------------------------------------------------------
pub struct Chain {
  chain: Vec<Stream>
}

impl Chain {
  pub fn new(genesis: Stream) -> Self {
    Self { chain: vec![genesis] }
  }

  pub fn current(&self) -> &Stream {
    self.chain.last().unwrap()
  }

  pub fn save(&mut self, stream: Stream) -> Result<()> {
    let srenew = stream.renew.as_ref().ok_or("Stream requires a renew block!")?;

    // verify current stream with renew stream key
    let st = self.current();
    st.verify_stream(&srenew.key)?;

    let mkey = srenew.renew.key.ok_or("Renew block requires a master public key!")?;
    let mcommit = commit(&mkey);

    // verify renew signature with master key
    if !srenew.renew.verify(&mkey) {
      return Err("Invalid renew!".into())
    }

    // check if group commit is correct
    if !st.groups.contains_key(&mcommit) {
      return Err("No group found on previous stream!".into())
    }

    // check chain
    if &srenew.renew.prev != st.prev() {
      return Err("Invalid stream chain!".into())
    }

    self.chain.push(stream);
    Ok(())
  }

  pub fn check(&self, key: &PublicKey) -> Result<()> {
    let mut mcommit: Option<String> = None;
    let mut prev: Option<&Signature> = None;
    let mut skey = Some(key);
    for st in self.chain.iter().rev() {
      if skey.is_none() {
        return Err("Chain contains more streams without a stream key!".into())
      }

      // check if group commit is correct
      if let Some(commit) = mcommit.as_ref() {
        if !st.groups.contains_key(commit) {
          return Err("No group found on previous stream!".into())
        }
      }

      // check chain
      if let Some(prev) = prev {
        if prev != st.prev() {
         return Err("Invalid stream chain!".into())
        }
      }

      // verify stream with stream key
      st.verify_stream(skey.unwrap())?;

      skey = match st.renew.as_ref() {
        None => None,
        Some(ext_renew) => {
          let srenew = &ext_renew.renew;
          let mkey = srenew.key.ok_or("Renew block requires a master public key!")?;

          // verify renew signature with master key
          if !srenew.verify(&mkey) {
            return Err("Invalid renew!".into())
          }

          mcommit = Some(commit(&mkey));
          prev = Some(&srenew.prev);
          Some(&ext_renew.key)
        }
      };
    }

    if skey.is_some() {
      return Err("Chain with invalid end!".into())
    }

    Ok(())
  }
}


#[cfg(test)]
mod tests {
  use super::*;
  use crate::structs::anchor::*;

  use rand::rngs::OsRng;
  use ed25519_dalek::Keypair;

  #[test]
  fn create_and_check_stream() {
    // anchor
    let udi = "udi-random";
    let r = "r-random";
    let mut csprng = OsRng{};
    let profile_keypair: Keypair = Keypair::generate(&mut csprng);
    let anchor = Anchor::new(&profile_keypair, udi, r, 0);

    // create stream
    let genesis = Record { oper: OType::SET, info: b"Not important!".to_vec() };
    let mut stream = Stream::new(&profile_keypair, udi, r, &vec![], genesis, None);
  
    // add block to stream
    let record = Record { oper: OType::SET, info: b"New info!".to_vec() };
    let block = StreamBlock::new(&profile_keypair, record, &stream.sig);
    stream.save(block).unwrap();

    // check if the stream is valid with the public key (verify all signatures)
    stream.verify_stream(&profile_keypair.public).unwrap();

    // check if ASI is connected to the anchor AL ?
    let al_sig = anchor.al_signature(&profile_keypair, udi);
    assert!(stream.check_asi(udi, r, &profile_keypair.public, &al_sig));
  }

  #[test]
  fn create_and_check_chain() {
    let udi = "udi-random";

    let mut csprng = OsRng{};
    let keypair1: Keypair = Keypair::generate(&mut csprng);
    let keypair2: Keypair = Keypair::generate(&mut csprng);

    // anchor-1 and anchor-2
    let r1 = "r1-random";
    let r2 = "r2-random";

    // master group for stream
    let m_keypair: Keypair = Keypair::generate(&mut csprng);
    let master = TLGroup::new(TLType::MASTER, &m_keypair.public);

    // stream-1
    let genesis = Record { oper: OType::SET, info: b"Not important!".to_vec() };
    let mut stream1 = Stream::new(&keypair1, udi, r1, &vec![master], genesis, None);

        // add block to stream
        let record = Record { oper: OType::SET, info: b"New info!".to_vec() };
        let block = StreamBlock::new(&keypair1, record, &stream1.sig);
        stream1.save(block).unwrap();

    // stream-2
    let ext_renew = ExtRenew {
      renew: Renew::new(&m_keypair, &keypair2.public, stream1.prev(), true),
      key: keypair1.public.clone()
    };

    let genesis = Record { oper: OType::SET, info: b"Not important!".to_vec() };
    let stream2 = Stream::new(&keypair2, udi, r2, &vec![], genesis, Some(ext_renew));

    // create and check chain
    let mut chain = Chain::new(stream1);
    chain.save(stream2).unwrap();

    // check chain (verify all signatures, master groups and renew blocks)
    chain.check(&keypair2.public).unwrap();
  }
}