use std::collections::BTreeMap;

use serde::{Serialize, Deserialize};
use ed25519_dalek::{Keypair, PublicKey, Signature};

use sha2::{Sha256, Digest};
use base64::encode;

pub type Result<T> = std::result::Result<T, String>;

fn commit(key: &PublicKey) -> String {
  let mut hasher = Sha256::new();
  hasher.input(key.as_bytes());
  let result = hasher.result();

  encode(&result)
}

//-----------------------------------------------------------------------------------------------------------
// Identity
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Identity {
    pub udi: String,
    pub cards: Vec<Card>,
    pub evols: Vec<Evolve>,
    
    enabled: bool
}

impl Identity {
  pub fn new(genesis: Card) -> Result<Self> {
    if !genesis.verify() {
      return Err("Invalid genesis card!".into())
    }

    Ok(Self { udi: commit(&genesis.key), cards: vec![genesis], evols: Vec::new(), enabled: true })
  }

  pub fn is_enabled(&self) -> bool {
    return self.enabled;
  }

  pub fn card(&self) -> &Card {
    // must always have a card
    self.cards.last().as_ref().unwrap()
  }

  pub fn prev(&self) -> Result<&Signature> {
    match self.enabled {
      true => Ok(&self.card().sig),
      false => match self.evols.last() {
        None => Err("Identity is disabled, must have evolutions!".into()),
        Some(current) => match &current.renew {
          Some(ev) => Ok(&ev.sig),
          None => Ok(&current.cancel.as_ref().ok_or("Expected to find cancel!")?.sig)
        }
      }
    }
  }

  pub fn cancel(&mut self, ev: Cancel) -> Result<()> {
    let card = self.card();

    // identity must be enabled
    if !self.enabled {
      return Err("Evolve is already in progress!".into())
    }

    // the last card must be referenced
    if card.sig != ev.prev {
      return Err("Invalid chain!".into())
    }

    // verify signature and public-key
    if !ev.verify() {
      return Err("Invalid cancel!".into())
    }

    // get the corresponding card group and disable identity
    let commit = commit(&ev.key);
    match card.groups.contains_key(&commit) {
      false => Err("No group found to evolve!".into()),
      true => {
        self.enabled = false;
        self.evols.push(Evolve { cancel: Some(ev), renew: None });
        Ok(())
      }
    }
  }

  pub fn renew(&mut self, ev: Renew) -> Result<()> {
    let card = self.card();

    // get the key to verify the signature
    let (key, evol) = match self.enabled {
      true => {
        // the last card must be referenced
        if card.sig != ev.prev {
          return Err("Invalid chain!".into())
        }

        // renew must also perform cancel
        match ev.key {
          None => return Err("Renew(cancel) must have a key!".into()),
          Some(key) => (key, Evolve { cancel: None, renew: Some(ev) })
        }
      },
      false => {
        // renew must evolve from an existing cancel
        match self.evols.last() {
          None => return Err("Identity is disabled, must have evolutions!".into()),
          Some(current) => {
            if current.cancel.is_none() || current.renew.is_some() {
              return Err("Identity in invalid state to perform a renew!".into())
            }

            let cancel = current.cancel.as_ref().unwrap();

            // the last cancel must be referenced
            if cancel.sig != ev.prev {
              return Err("Invalid chain!".into())
            }

            (cancel.key, Evolve { cancel: Some(cancel.clone()), renew: Some(ev) })
          }
        }
      }
    };

    // verify signature and public-key
    if !evol.renew.as_ref().unwrap().verify(&key) {
      return Err("Invalid renew!".into())
    }

    // get the corresponding card group and disable identity
    let commit = commit(&key);
    match card.groups.get(&commit) {
      None => Err("No group found to evolve!".into()),
      Some(gr) => {
        //TODO: can I evolve to a new key?

        self.enabled = false;
        match evol.cancel {
          None => self.evols.push(evol),  // push new evolve
          Some(_) => {
            // replace existing evolve
            let index = self.evols.len() - 1;
            self.evols[index] = evol;
          }            
        }
        
        Ok(())
      }
    }
  }

  pub fn evolve(&mut self, card: Card) -> Result<()> {
    if self.enabled {
      return Err("Cannot evolve an enabled identity!".into())
    }

    let renew = self.evols.last().as_ref()
      .ok_or("Identity is disabled, must have evolutions!")?.renew.as_ref()
      .ok_or("A renew must exist to evolve!")?;
    
    if renew.commit != commit(&card.key) {
      return Err("The commit is not valid!".into())
    }

    if !card.verify() {
      return Err("Invalid card!".into())
    }

    self.enabled = true;
    self.cards.push(card);

    Ok(())
  }
}

//-----------------------------------------------------------------------------------------------------------
// Card
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Card {
  pub info: Vec<u8>,
  pub groups: BTreeMap<String, TLGroup>,
  pub sig: Signature,
  key: PublicKey
}

impl Card {
  pub fn new(keypair: &Keypair, info: &[u8], groups: &[TLGroup]) -> Self {
    let mut g_map = BTreeMap::<String, TLGroup>::new();
    for gr in groups.into_iter() {
      g_map.insert(gr.commit.clone(), gr.clone());
    }

    let sig_data = Self::data(info, &g_map);
    let sig = keypair.sign(&sig_data);

    Self { info: info.into(), groups: g_map, sig, key: keypair.public }
  }

  pub fn verify(&self) -> bool {
    let sig_data = Self::data(&self.info, &self.groups);
    self.key.verify(&sig_data, &self.sig).is_ok()
  }

  fn data(info: &[u8], groups: &BTreeMap<String, TLGroup>) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    // These unwrap() should never fail, or it's a serious code bug!
    data.extend(bincode::serialize(info).unwrap());
    data.extend(bincode::serialize(groups).unwrap());
    
    data
  }
}

//-----------------------------------------------------------------------------------------------------------
// TLType & TLGroup
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TLType { MASTER, SLAVE }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TLGroup {
  pub typ: TLType,
  pub commit: String,
  #[serde(skip)] _phantom: ()
}

impl TLGroup {
  pub fn new(typ: TLType, key: &PublicKey) -> Self {
    Self { typ, commit: commit(key), _phantom: () }
  }
}

//-----------------------------------------------------------------------------------------------------------
// Evolve
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Evolve {
  pub cancel: Option<Cancel>,
  pub renew: Option<Renew>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cancel {
  pub prev: Signature,
  pub sig: Signature,
  key: PublicKey
}

impl Cancel {
  pub fn new(keypair: &Keypair, prev: &Signature) -> Self {
    let sig_data = Self::data(prev);
    let sig = keypair.sign(&sig_data);

    Self { prev: prev.clone(), sig, key: keypair.public }
  }

  pub fn verify(&self) -> bool {
    let sig_data = Self::data(&self.prev);
    self.key.verify(&sig_data, &self.sig).is_ok()
  }

  fn data(prev: &Signature) -> Vec<u8> {
    // These unwrap() should never fail, or it's a serious code bug!
    bincode::serialize(prev).unwrap().into()
  }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Renew {
  pub commit: String,
  pub prev: Signature,
  pub sig: Signature,
  key: Option<PublicKey>
}

impl Renew {
  pub fn new(keypair: &Keypair, next: &PublicKey, prev: &Signature, inc_key: bool) -> Self {
    let commit = commit(next);

    let sig_data = Self::data(&commit, &prev);
    let sig = keypair.sign(&sig_data);

    let key = if inc_key {
      Some(keypair.public)
    } else {
      None
    };

    Self { commit, prev: prev.clone(), sig, key }
  }

  pub fn verify(&self, key: &PublicKey) -> bool {
    let sig_data = Self::data(&self.commit, &self.prev);
    key.verify(&sig_data, &self.sig).is_ok()
  }

  fn data(commit: &str, prev: &Signature) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    // These unwrap() should never fail, or it's a serious code bug!
    data.extend(bincode::serialize(commit).unwrap());
    data.extend(bincode::serialize(prev).unwrap());
    
    data
  }
}