# RAIAP
RAIAP: Renewable Authentication on Isolated Anonymous Profiles
A GDPR compliant self-sovereign architecture for distributed systems

## Abstract
Implementing pseudonymity, key-management, non-repudiation and data minimisation features in isolated procedures is trivial. However, integrating all of them in one consistent architecture has several challenges to tackle. This work proposes data structures to represent Self-Sovereign Identities and to handle those features in a consolidated architecture. Key-management is constructed using secret sharing principles, capable of recovering from a lost or compromised key to a new one without losing track of the original account. Pseudonymity and data minimisation is established using anonymous profiles, showing different views of the same identity. Non-repudiation is contemplated in the profile disclosure process. Profiles are protected against tampering with the use of digital signatures and blockchain cryptographic constructions. All profiles and registries are controlled with a single asymmetric key pair that can be provided by a smart card. Flexible structures are defined that can be used to register claims, attestations, authorisation grants, user consents, or any other activities. All definitions take into consideration the rules of the General Data Protection Regulation (GDPR).

## Dependencies
* rustc > 1.36.0
* cargo > 1.36.0

## Results
This project implements the data structures presented in the RAIAP publication.
Run with
```cargo test```

The results are in the form of unit tests. There are 3 groups of tests identity, anchor and stream.
* identity - testing the cards and evolutions
* anchor - testing the anchor data structures
* stream - testing the streams and chains
