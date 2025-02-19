# Online Veterinary Services(OnlineVetCare)

## Description

This project provides a comprehensive online platform for veterinary services. It enables pet owners to manage their pets' health, schedule appointments with veterinarians, and keep track of health records. Veterinarians can manage appointments, health records, and prescriptions. Additionally, the platform supports online payment for services and facilitates pet adoption and fostering.

## Features

- **User Management:** Register and manage users with roles such as Pet Owner, Veterinarian, and Admin.
- **Pet Management:** Add and manage pets, including details like name, species, breed, and age.
- **Appointment Scheduling:** Schedule appointments between pet owners and veterinarians.
- **Health Records Management:** Veterinarians can add and view health records for pets.
- **Prescription Management:** Allow veterinarians to prescribe medications and track prescriptions for pets.
- **Messaging:** Send and receive messages between users.
- **Notification System:** Admins can send notifications to users.
- **Online Payment Integration:** Integrate with payment gateways to allow pet owners to pay for appointments and services online.
- **Pet Adoption and Fostering:** Include a platform for pet adoption and fostering services.


### Secure and Decentralized
- The system leverages the decentralized nature of the Internet Computer for secure and tamper-proof operations.





## Requirements
* rustc 1.64 or higher
```bash
$ curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
$ source "$HOME/.cargo/env"
```
* rust wasm32-unknown-unknown target
```bash
$ rustup target add wasm32-unknown-unknown
```
* candid-extractor
```bash
$ cargo install candid-extractor
```
* install `dfx`
```bash
$ DFX_VERSION=0.15.0 sh -ci "$(curl -fsSL https://sdk.dfinity.org/install.sh)"
$ echo 'export PATH="$PATH:$HOME/bin"' >> "$HOME/.bashrc"
$ source ~/.bashrc
$ dfx start --background
```

If you want to start working on your project right away, you might want to try the following commands:

```bash
$ cd icp_rust_boilerplate/
$ dfx help
$ dfx canister --help
```

## Update dependencies

update the `dependencies` block in `/src/{canister_name}/Cargo.toml`:
```
[dependencies]
candid = "0.9.9"
ic-cdk = "0.11.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1.0"
ic-stable-structures = { git = "https://github.com/lwshang/stable-structures.git", branch = "lwshang/update_cdk"}
```

## did autogenerate

Add this script to the root directory of the project:
```
https://github.com/buildwithjuno/juno/blob/main/scripts/did.sh
```

Update line 16 with the name of your canister:
```
https://github.com/buildwithjuno/juno/blob/main/scripts/did.sh#L16
```

After this run this script to generate Candid.
Important note!

You should run this script each time you modify/add/remove exported functions of the canister.
Otherwise, you'll have to modify the candid file manually.

Also, you can add package json with this content:
```
{
    "scripts": {
        "generate": "./did.sh && dfx generate",
        "gen-deploy": "./did.sh && dfx generate && dfx deploy -y"
      }
}
```

and use commands `npm run generate` to generate candid or `npm run gen-deploy` to generate candid and to deploy a canister.

## Running the project locally

If you want to test your project locally, you can use the following commands:

```bash
# Starts the replica, running in the background
$ dfx start --background

# Deploys your canisters to the replica and generates your candid interface
$ dfx deploy
```