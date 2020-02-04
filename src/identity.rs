use std::collections::BTreeMap;
use std::collections::HashMap;

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
    
    pub db: HashMap<String, Vec<Registry>>,
    enabled: bool
}

impl Identity {
  pub fn new(genesis: Card) -> Result<Self> {
    if !genesis.verify() {
      return Err("Invalid genesis card!".into())
    }

    Ok(Self { udi: commit(&genesis.key), cards: vec![genesis], evols: Vec::new(), db: HashMap::new(), enabled: true })
  }

  pub fn is_enabled(&self) -> bool {
    return self.enabled;
  }

  pub fn card(&self) -> &Card {
    // must always have a card
    self.cards.last().as_ref().unwrap()
  }

  pub fn registry(&self, id: &str) -> Option<&Vec<Registry>> {
    self.db.get(id)
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

  pub fn save(&mut self, registry: Registry) -> Result<()> {
    if !self.enabled {
      return Err("Identity is disabled!".into())
    }

    { // scope for immutable borrow
      let card = self.card();
      if self.cards.len() - 1 != registry.key_index {
        return Err("Invalid key index!".into())
      }

      if !registry.verify(&card.key) {
        return Err("Invalid registry!".into())
      }
    }

    let chain = self.db.get_mut(&registry.id);
    match chain {
      None => {
        let card = self.card();
        if card.sig != registry.prev {
          return Err("Invalid chain!".into())
        }

        let id = registry.id.clone();
        let reg = vec![registry];
        self.db.insert(id, reg);
      },

      Some(reg) => {
        // should always exist
        let current = reg.last().unwrap();
        if current.sig != registry.prev {
          return Err("Invalid chain!".into())
        }

        if registry.typ != current.typ {
          return Err("Invalid chain (dif type)!".into())
        }

        reg.push(registry);
      }
    }

    Ok(())
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
    match card.groups.get(&commit) {
      None => Err("No group found to evolve!".into()),
      Some(gr) => {
        if ev.is_close && gr.typ != TLType::MASTER {
          return Err("Only master groups can close permanently!".into())
        }

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
            
            // is it closed permanently?
            if cancel.is_close {
              return Err("Identity closed permanently!".into())
            }

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
      Some(_) => {
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

    if card.is_genesis {
      return Err("Cannot evolve to a genesis card!".into())
    }

    let renew = self.evols.last().as_ref()
      .ok_or("Identity is disabled, must have evolutions!")?.renew.as_ref()
      .ok_or("A renew must exist to evolve!")?;
    
    if renew.commit != commit(&card.key) {
      return Err("The card key is not valid!".into())
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
  pub is_genesis: bool,
  pub info: Vec<u8>,
  pub groups: BTreeMap<String, TLGroup>,
  pub sig: Signature,
  key: PublicKey
}

impl Card {
  pub fn new(is_genesis: bool, keypair: &Keypair, info: &[u8], groups: &[TLGroup]) -> Self {
    let mut g_map = BTreeMap::<String, TLGroup>::new();
    for gr in groups.into_iter() {
      g_map.insert(gr.commit.clone(), gr.clone());
    }

    let sig_data = Self::data(is_genesis, info, &g_map);
    let sig = keypair.sign(&sig_data);

    Self { is_genesis, info: info.into(), groups: g_map, sig, key: keypair.public }
  }

  pub fn verify(&self) -> bool {
    let sig_data = Self::data(self.is_genesis, &self.info, &self.groups);
    self.key.verify(&sig_data, &self.sig).is_ok()
  }

  fn data(is_genesis: bool, info: &[u8], groups: &BTreeMap<String, TLGroup>) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    // These unwrap() should never fail, or it's a serious code bug!
    data.extend(bincode::serialize(&is_genesis).unwrap());
    data.extend(bincode::serialize(info).unwrap());
    data.extend(bincode::serialize(groups).unwrap());
    
    data
  }
}

//-----------------------------------------------------------------------------------------------------------
// TLType & TLGroup
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
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
  pub is_close: bool,
  pub prev: Signature,
  pub sig: Signature,
  key: PublicKey
}

impl Cancel {
  pub fn new(is_close: bool, keypair: &Keypair, prev: &Signature) -> Self {
    let sig_data = Self::data(is_close, prev);
    let sig = keypair.sign(&sig_data);

    Self { is_close, prev: prev.clone(), sig, key: keypair.public }
  }

  pub fn verify(&self) -> bool {
    let sig_data = Self::data(self.is_close, &self.prev);
    self.key.verify(&sig_data, &self.sig).is_ok()
  }

  fn data(is_close: bool, prev: &Signature) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    // These unwrap() should never fail, or it's a serious code bug!
    data.extend(bincode::serialize(&is_close).unwrap());
    data.extend(bincode::serialize(prev).unwrap());
    
    data
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

//-----------------------------------------------------------------------------------------------------------
// Registry
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum OType { SET, DEL }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Registry {
  pub id: String,  // (Domain, Name)
  pub typ: String,
  pub oper: OType,

  pub info: Vec<u8>,
  pub prev: Signature,
  pub sig: Signature,
  key_index: usize
}

impl Registry {
  pub fn new(keypair: &Keypair, id: &str, typ: &str, oper: OType, info: &[u8], prev: &Signature, key_index: usize) -> Self {
    let sig_data = Self::data(&id, &typ, &oper, &info, prev);
    let sig = keypair.sign(&sig_data);

    Self { id: id.into(), typ: typ.into(), oper, info: info.into(),  prev: prev.clone(), sig, key_index }
  }

  pub fn verify(&self, key: &PublicKey) -> bool {
    let sig_data = Self::data(&self.id, &self.typ, &self.oper, &self.info, &self.prev);
    key.verify(&sig_data, &self.sig).is_ok()
  }

  fn data(id: &str, typ: &str, oper: &OType, info: &[u8], prev: &Signature) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    // These unwrap() should never fail, or it's a serious code bug!
    data.extend(bincode::serialize(id).unwrap());
    data.extend(bincode::serialize(typ).unwrap());
    data.extend(bincode::serialize(oper).unwrap());
    data.extend(bincode::serialize(info).unwrap());
    data.extend(bincode::serialize(prev).unwrap());
    
    data
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::rngs::OsRng;
  use ed25519_dalek::Keypair;

  fn create() -> (Identity, TLGroup, Keypair, Keypair) {
    let mut csprng = OsRng{};

    // create master group
    let m_keypair: Keypair = Keypair::generate(&mut csprng);
    let master = TLGroup::new(TLType::MASTER, &m_keypair.public);

    // create genesis card and identity
    let id_keypair: Keypair = Keypair::generate(&mut csprng);
    let genesis = Card::new(true, &id_keypair, b"No important info!", &vec![master.clone()]);
    let identity = Identity::new(genesis).unwrap();
    
    (identity, master, m_keypair, id_keypair)
  }

  #[test]
  fn create_and_evolve() {
    let mut csprng = OsRng{};
    let (mut identity, master, m_keypair, _) = create();
    assert!(identity.is_enabled());

    // cancel identity with the master group
    let cancel = Cancel::new(false, &m_keypair, identity.prev().unwrap());
    identity.cancel(cancel).unwrap();
    assert!(!identity.is_enabled());

    // renew identity with the master group
    let id_keypair2: Keypair = Keypair::generate(&mut csprng);
    let renew = Renew::new(&m_keypair, &id_keypair2.public, identity.prev().unwrap(), false);
    identity.renew(renew).unwrap();
    assert!(!identity.is_enabled());

    // evolve identity to the new card (commited in the renew)
    let card2 = Card::new(false, &id_keypair2, b"No info!", &vec![master.clone()]);
    identity.evolve(card2).unwrap();
    assert!(identity.is_enabled());
  }

  #[test]
  fn direct_renew() {
    let mut csprng = OsRng{};
    let (mut identity, master, m_keypair, _) = create();

    // renew performs an implicit cancel
    let id_keypair2: Keypair = Keypair::generate(&mut csprng);
    let renew = Renew::new(&m_keypair, &id_keypair2.public, identity.prev().unwrap(), true);
    identity.renew(renew).unwrap();

    // evolve identity to the new card (commited in the renew)
    let card2 = Card::new(false, &id_keypair2, b"No info!", &vec![master.clone()]);
    identity.evolve(card2).unwrap();
    assert!(identity.is_enabled());
  }

  #[test]
  fn closed_permanently() {
    let mut csprng = OsRng{};
    let (mut identity, _, m_keypair, _) = create();

    // close identity permanently
    let cancel = Cancel::new(true, &m_keypair, identity.prev().unwrap());
    identity.cancel(cancel).unwrap();

    // renew must fail
    let id_keypair2: Keypair = Keypair::generate(&mut csprng);
    let renew = Renew::new(&m_keypair, &id_keypair2.public, identity.prev().unwrap(), false);
    assert!(identity.renew(renew) == Err("Identity closed permanently!".into()));
  }

  #[test]
  fn fail_on_wrong_key() {
    let mut csprng = OsRng{};
    let (mut identity, master, m_keypair, _) = create();

    // renew performs an implicit cancel
    let id_keypair2: Keypair = Keypair::generate(&mut csprng);
    let renew = Renew::new(&m_keypair, &id_keypair2.public, identity.prev().unwrap(), true);
    identity.renew(renew).unwrap();

    // fail when evolving the identity to a wrong card (different key from the one in renew/commit)
    let id_keypair3: Keypair = Keypair::generate(&mut csprng);
    let card2 = Card::new(false, &id_keypair3, b"No info!", &vec![master.clone()]);
    assert!(identity.evolve(card2) == Err("The card key is not valid!".into()));
  }

  #[test]
  fn fail_when_disabled() {
    let mut csprng = OsRng{};
    let (mut identity, master, m_keypair, _) = create();

    // cancel identity with the master group
    let cancel = Cancel::new(false, &m_keypair, identity.prev().unwrap());
    identity.cancel(cancel).unwrap();

    // fail when identity is disabled
    let id_keypair2: Keypair = Keypair::generate(&mut csprng);
    let card2 = Card::new(false, &id_keypair2, b"No info!", &vec![master.clone()]);
    assert!(identity.evolve(card2) == Err("A renew must exist to evolve!".into()));
  }

  #[test]
  fn invalid_chain() {
    let mut csprng = OsRng{};
    let (mut identity, _, m_keypair, _) = create();

    let previous_card = identity.prev().unwrap().clone();

    // cancel identity with the master group
    let cancel = Cancel::new(false, &m_keypair, &previous_card);
    identity.cancel(cancel).unwrap();

    // fail when renewing with an invalid chain (pointing to the previous card instead of cancel)
    let id_keypair2: Keypair = Keypair::generate(&mut csprng);
    let renew = Renew::new(&m_keypair, &id_keypair2.public, &previous_card, false);
    assert!(identity.renew(renew) == Err("Invalid chain!".into()));
  }

  #[test]
  fn signature_failed() {
    let (mut identity, _, m_keypair, _) = create();

    // cancel identity with the master group
    let mut cancel1 = Cancel::new(true, &m_keypair, identity.prev().unwrap());
    let cancel2 = Cancel::new(false, &m_keypair, identity.prev().unwrap());
    cancel1.sig = cancel2.sig;
    assert!(identity.cancel(cancel1) == Err("Invalid cancel!".into()));
  }

  #[test]
  fn no_group_found() {
    let mut csprng = OsRng{};
    let (mut identity, _, _, _) = create();

    // cancel identity with a non existing group
    let m_keypair: Keypair = Keypair::generate(&mut csprng);
    let cancel = Cancel::new(false, &m_keypair, identity.prev().unwrap());
    assert!(identity.cancel(cancel) == Err("No group found to evolve!".into()))
  }

  #[test]
  fn insert_registry() {
    let (mut identity, _, _ , id_keypair) = create();

    let reg1 = Registry::new(&id_keypair, "idp.io", "test", OType::SET, b"Not important!", identity.prev().unwrap(), 0);
    assert!(identity.save(reg1.clone()) == Ok(()));

    let reg2 = Registry::new(&id_keypair, "idp.io", "test", OType::SET, b"More info!", &reg1.sig, 0);
    assert!(identity.save(reg2) == Ok(()));
  }

  #[test]
  fn insert_registry_invalid_chain() {
    let (mut identity, _, _ , id_keypair) = create();

    let reg1 = Registry::new(&id_keypair, "idp.io", "test", OType::SET, b"Not important!", identity.prev().unwrap(), 0);
    assert!(identity.save(reg1) == Ok(()));
    
    let reg2 = Registry::new(&id_keypair, "idp.io", "test", OType::SET, b"More info!", identity.prev().unwrap(), 0);
    assert!(identity.save(reg2) == Err("Invalid chain!".into()));
  }

  #[test]
  fn insert_registry_invalid_key_index() {
    let (mut identity, _, _ , id_keypair) = create();

    let reg = Registry::new(&id_keypair, "idp.io", "test", OType::SET, b"Not important!", identity.prev().unwrap(), 1);
    assert!(identity.save(reg) == Err("Invalid key index!".into()));
  }
}