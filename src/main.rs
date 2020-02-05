mod structs;

use structs::*;
use structs::identity::*;
use structs::anchor::*;
use structs::stream::*;

use rand::rngs::OsRng;
use ed25519_dalek::Keypair;

fn main() {
  let mut csprng = OsRng{};
  
  // create master group
  let m_keypair: Keypair = Keypair::generate(&mut csprng);
  let master = TLGroup::new(TLType::MASTER, &m_keypair.public);

  // create genesis card and identity
  let id_keypair: Keypair = Keypair::generate(&mut csprng);
  let genesis = Card::new(true, &id_keypair, b"No important info!", &vec![master.clone()]);
  let mut identity = Identity::new(genesis).unwrap();
  println!("NEW-ID: {:?}", identity.udi);
  println!("ID-ENABLED: {:?}", identity.is_enabled());

  // evolve identity with the master group
  let cancel = Cancel::new(false, &m_keypair, identity.prev().unwrap());
  identity.cancel(cancel).unwrap();
  println!("ID-ENABLED: {:?}", identity.is_enabled());

  let id_keypair2: Keypair = Keypair::generate(&mut csprng);
  let renew = Renew::new(&m_keypair, &id_keypair2.public, identity.prev().unwrap(), false);
  identity.renew(renew).unwrap();
  //println!("ID: {:#?}", identity.evols);

  let card2 = Card::new(false, &id_keypair2, b"No info!", &vec![master.clone()]);
  identity.evolve(card2).unwrap();
  println!("ID-ENABLED: {:?}", identity.is_enabled());

  // insert registry
  let reg = Registry::new(&id_keypair2, "idp.io/test", "test", OType::SET, b"Not important!", identity.prev().unwrap(), 1);
  identity.save(reg).unwrap();

  // insert anchor
  let r = "some-random";
  let profile_keypair: Keypair = Keypair::generate(&mut csprng);
  let anchor = Anchor::new(&profile_keypair, &identity.udi, r, 0);
  let anchor_reg = Registry::new(&id_keypair2, "raiap.io/test", "anchor", OType::SET, &anchor.to_bytes(), identity.prev().unwrap(), 1);
  identity.save(anchor_reg).unwrap();

  // construct profile stream
  let genesis = Record { oper: OType::SET, info: b"Not important!".to_vec() };
  let mut stream = Stream::new(&profile_keypair, &identity.udi, r, &vec![], genesis);

  // add block to stream
  let record = Record { oper: OType::SET, info: b"New info!".to_vec() };
  let block = StreamBlock::new(&profile_keypair, record, &stream.sig);
  stream.save(block).unwrap();

  stream.verify_chain(&profile_keypair.public).unwrap();

  let al_sig = anchor.al_signature(&profile_keypair, &identity.udi);
  println!("ASI: {:?}", stream.check_asi(&identity.udi, r, &profile_keypair.public, &al_sig));
}