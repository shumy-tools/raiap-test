mod identity;

use identity::*;

use rand::rngs::OsRng;
use ed25519_dalek::Keypair;

fn main() {
  let mut csprng = OsRng{};
  
  // create master group
  let m_keypair: Keypair = Keypair::generate(&mut csprng);
  let master = TLGroup::new(TLType::MASTER, &m_keypair.public);

  // create genesis card and identity
  let id_keypair: Keypair = Keypair::generate(&mut csprng);
  let genesis = Card::new(&id_keypair, b"No important info!", &vec![master.clone()]);
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

  let card2 = Card::new(&id_keypair2, b"No info!", &vec![master.clone()]);
  identity.evolve(card2).unwrap();
  println!("ID-ENABLED: {:?}", identity.is_enabled());
}