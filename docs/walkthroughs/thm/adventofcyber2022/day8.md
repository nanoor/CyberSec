---
title: Day 08 - Smart Contracts
desc: >-
  Day 8 covers topics related to smart contracts, what they are, how they relate
  to the blockchain, and why they are important. 
---
## Blockchain

A blockchain is a digital database or ledger distributed among nodes of a peer-to-peer network. It acts as a database to store information in a specified format and is shared among members of a network with no one entity in control (decentralized). Due to its decentralized nature, each peer is expected to maintain the integrity of the blockchain. If one member of the network attempted to modify a blockchain maliciously, other members would compare it to their blockchain for integrity and determine if the whole network should express that change.

## Smart Contracts

A smart contract is a program stored on a blockchain that runs when pre-determined conditions are met. At its core, a smart contracts waits for a specific condition to be satisfied before executing preprogrammed actions. This is similar to traditional logic works. Once a smart contract is deployed on a blockchain, another contract can call or execute its functions. Note that a smart contract can consecutively make new calls to a function while an old function is still executing. This can lead to issues which can be exploited by threat actors.

Most smart contract vulnerabilities arise due to logic issues or poor exception handling. Most vulnerabilities arise in functions when conditions are insecurely implemented. Refer to today's challenge for more information on `Re-entrancy Attacks`.

## CTF Questions

Follow instructions on the task to complete the challenge and retrieve the flag: `flag{411_ur_37h_15_m1n3}`