Nym is [nymtech.net](https://nymtech.net)

---

Deonym utilizes Nym's **Single Use Reply Blocks** (SURBs) to ship traffic to
services.

This is intended to help with security and anonymity.

A server's Nym address is substituted with a physical unique identifier, which
is internally used for identification. **Only the Wingman's Nym address is ever
published.**

Components:

- Wingman - Publishes their Nym address instead of the actual service and
  buffers ingoing queries until they are delegated to the respective authority.
- Client - Sends its query to a Wingman, nesting any SURB within the Deon frame.
  The service is identified by its public key, which allows the query to be
  encrypted.
- Service - Can ask to be delegated any queries on a Wingman by sending their
  signature in order to validate their authority.

Deonym introduces the Deon protocol, which is a tiny communication standard for
the Deonym platform. There are two primary methods supported by Deon:

- PUT - Frame for payloads and SURBs.
- POP - Frame for delegations.

> Since keypairs are physical, with Deonym **a service doesn't have an address-
> an address has a service.** It is critical that private keys are never leaked
> and I hope that in the near future we can introduce a PKI system that works
> not not much unlike DNS for addressation.

## Tracking

Tracking on which Wingmen which Services are seeded can be solved with either a
central tracker or signature address propagation, a method in which Services
tell Clients where they are seeding in their response.

## Stateless vs Stateful

Always going all the way over the Wingman route not only doubles the amount of
Nym-hops needed, it also requires asymetrically encrypting and decrypting every
query because we don't want the Wingman to be able to look into the payload.
However, it is possible to only use the full, stateless, route to establish a
_stateful_ connection via SURBs (i.e. nested SURBs in responses from a Service).
Such a stateful connection completely skips the Wingman and would require no
additional layer of encryption. This is **deemed unsafe for now**, as it allows
anyone to "generate" SURBs to a service, possibly preceding DoS attacks meant to
deanonymize a service. The Nym team will have to make the call here.

## SURB nesting

Deonym utilizes SURBs where Nym does not expect them. This requires Deonym to
jerry-rig the system, dynamically sending messages to itself to harvest SURBs.
This may change in the future, but for now requires a workaround.

## Frames

|     | Request                        | Response                  |
| --- | ------------------------------ | ------------------------- |
| PUT | `[1] [8] [?] [8] [?] [8] [?]`  | `[1] [8] [?] [8] [?]`     |
|     | `TAG LEN PEM LEN PAY LEN SURB` | `TAG LEN PAY LEN SURB`    |
| POP | `[1] [96] [8] [?] [8] [?]`     | `[1] [96] [8] [8]:[?] ..` |
|     | `TAG WING LEN PEM LEN SIG`     | `TAG WING SIZ LEN VEC`    |
