# 👋 Whiteflag CLI

The whiteflag CLI allows users to interact with the whiteflag protocol contextualized to the fennel ecosystem.

## Getting Started

`wf encode` and `wf decode` do not require authentication since they are not meant to send messages by any particular user, they only convert to and from the hexadecimal format.

In order to use `wf message <CODE>`, the user must first authenticate. This can be done by running `wf auth`.

When the user is done, they can exit their session by running `wf auth logout`.

## Examples

Run `wf help` to get a list of all the commands available to you. In the following documentation, you will find examples of how to use each command.

#### Encode

```
cargo wf encode "{\"prefix\":\"WF\",\"version\":\"1\",\"encryptionIndicator\":\"0\",\"duressIndicator\":\"0\",\"messageCode\":\"A\",\"referenceIndicator\":\"0\",\"referencedMessage\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"verificationMethod\":\"1\",\"verificationData\":\"https://organisation.int/whiteflag\"}"
```

#### Decode

```
cargo wf decode 5746313020800000000000000000000000000000000000000000000000000000000000000000b43a3a38399d1797b7b933b0b734b9b0ba34b7b71734b73a17bbb434ba32b33630b380
```

#### Auth

Create an authentication session

```
cargo wf auth
```

Logout from your active authentication session

```
cargo wf auth logout
```

#### Message

This command allows a user to send a whiteflag message onto the blockchain.

NOTE: an active authentication session is required before using this command. Create one using `wf auth`.

```
cargo wf message A
```

Supported Message Codes:

- A => Authentication
- R => Resource
- F => FreeText
- P => Protective
- E => Emergency
- D => Danger
- S => Status
- I => Infrastructure
- M => Mission

```
cargo wf message D -> <ContentID> from IFPS
cargo ipfs get-file <ContentID> -> <MESSAGE> (in hexadecimal)
cargo wf decode <MESSAGE> -> whiteflag message in json format
```
