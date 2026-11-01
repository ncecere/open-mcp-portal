# SCIM 2.0 provisioning

Decision 92. An identity provider (Entra ID, Okta, authentik, …) can create, update, deactivate and delete people and groups in Open MCP Portal through SCIM 2.0 ([RFC 7643](https://www.rfc-editor.org/rfc/rfc7643), [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644)). Sign-in stays OIDC: SCIM never authenticates anyone.

## Setting it up

1. Configure single sign-on (OIDC). Provisioning binds to that issuer and can't be set up without it.
2. **Admin › Provisioning:** set up the directory, choose the enrollment policy and enable it.
3. Create a provisioning token (`ompscim_…`, shown once, 1–365 days, at most 5 active). Give the identity provider the **SCIM base URL** shown on the page (`<APP_URL>/scim/v2`) and the token as a bearer token.
4. Configure the identity provider to send **`externalId` = the OIDC `sub`** it issues for that person (in Entra ID, map `objectId` to `externalId` when the portal's OIDC subject is the object ID; in authentik, the user's subject mode must match). This is the only link between a provisioned person and a signed-in identity.
5. Optionally map directory groups to team roles (admin, editor or member).

A provisioning token authenticates only `/scim/v2`; it is refused by `/v1` and `/mcp`, and a token or session can't call `/scim/v2`. Tokens belong to the directory rather than the admin who made them, so they keep working when that admin leaves; revoke them on the same page. Directory writes are audited as `scim.*` system entries naming the token.

## Who is directory managed

A provisioned resource is **not** an identity. It links to a portal person only when its `externalId` equals that person's verified OIDC subject for the configured issuer:

- **New people** are enrolled at their first sign-in, if exactly one active resource has their subject as `externalId`. An inactive resource, more than one candidate, or (with required enrollment) no resource refuses the sign-in before any user, invite, bootstrap or session is created.
- **People who already signed in** are not taken over automatically. Admin › Provisioning lists each resource's matching existing person; an admin **adopts** them explicitly.
- Email addresses and `userName` never link accounts.
- **Platform admins and team owners are never directory managed.** They can't be adopted, a managed person can't be promoted to either, and a bootstrap administrator never enrolls as managed. Keep at least one unmanaged administrator for break-glass access. An owner invitation stays pending for a managed person.

**Enrollment policy.** *Optional* lets a new identity without a resource sign in unmanaged, as before (a later push does not adopt them). *Required* refuses such new identities. In both cases, existing unmanaged people keep signing in.

## Lifecycle

| Directory change | Effect in the portal |
| --- | --- |
| `active: false` | The person is suspended at once: their browser sessions end (without deleting the rows), requests already in flight can't mint keys, and every key, OAuth token and connection is refused while inactive. Credentials are kept. |
| `active: true` | The directory restriction lifts. Earlier browser sessions stay ended; the person signs in again. Keys and connections that were not revoked work again for new requests. A manual suspension still applies. |
| `DELETE` | Irreversible for that account life: the person is suspended at once, and a clean-up job deletes their sessions, OAuth grants, personal connections, personal secrets and team memberships and user grants, and revokes their API keys. Audit and call history are kept; team-owned credentials and servers they set up are not touched. Remote revocation at providers is not attempted. |
| re-creating a deleted person | A new resource does not revive the old account. After clean-up completes, an admin **re-enrolls** the person on Admin › Provisioning. |

Turning provisioning off refuses the identity provider's tokens and stops gating sign-in, but leaves each managed person's directory standing as it was: someone deactivated stays suspended. Unlink people on Admin › Provisioning to return them to manual control.

Manual and directory standing are separate: an admin's suspension and the directory's deactivation each block on their own, and lifting one never lifts the other. The user's effective status is shown with both.

Clean-up runs on every replica in bounded passes. When an artifact is locked (for example a provider connection in the middle of a token refresh), the pass stops, records `incomplete` and is retried; it completes only when a recount finds nothing left.

## Groups and team roles

Directory groups carry memberships. A platform admin maps a group to a team with a role (admin, editor or member; never owner). A person's directory role in a team is the highest role among their mapped groups.

- The directory only manages memberships it created. A membership someone added by hand is never changed or removed, even if the person is also in a mapped group.
- Changing a directory-created membership by hand takes it over: it becomes manual.
- Removing a person from a group, deleting the group or deleting the mapping removes the memberships only that group gave.
- Archived teams receive no new directory memberships.

**Gateway SSO-group grants are separate.** Gateway grants to an SSO group still use the `groups` claim from the person's latest OIDC sign-in, as before; SCIM groups don't change them. Deactivating or deleting a person blocks all of their access regardless.

## Protocol profile

Base URL `/scim/v2`, `application/scim+json`, bearer token.

- **Users:** `GET` (list, by id), `POST`, `PUT`, `PATCH`, `DELETE`. Attributes: `userName` (required, unique ignoring case), `externalId` (case-exact), `active`, `displayName`, `name.givenName`, `name.familyName`, `emails` (the primary one is kept); `groups` is read-only. Unknown and extension attributes are ignored.
- **Groups:** the same verbs. `displayName` (required, unique ignoring case; a duplicate create or rename gets `409 uniqueness`), `externalId`, `members` (must be provisioned users of this directory; one unknown member fails the request).
- **PATCH** ([RFC 7644 §3.5.2](https://www.rfc-editor.org/rfc/rfc7644#section-3.5.2)) is atomic and applied in order; `op` is case-insensitive; `"True"`/`"False"` strings are accepted for `active`; paths include `members[value eq "…"]` and `emails[type eq "work"].value`. At most 100 operations and 1,000 members per operation.
- **Filtering:** `attribute eq "value"` on `userName`, `externalId` and `id` (users) and `displayName`, `externalId` and `id` (groups). Other filters are `400 invalidFilter`.
- **Pagination:** `startIndex` (below 1 means 1) and `count` (negative means 0, at most 200). No sorting.
- **Versions:** each resource has a weak ETag (`W/"n"`); `If-Match` on `PUT`, `PATCH` and `DELETE` is honoured (`412` on mismatch).
- An empty group is returned with `"members": []`; `excludedAttributes=members` omits members.
- Discovery: `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`. Bulk, sorting and password change are not supported.

A PATCH without the top-level `schemas` member is accepted (authentik 2025.x sends attribute updates that way); one that declares other schemas without PatchOp is refused.

### Provider notes

- **authentik 2025.8** (tested with a real local push): users, enrollment by OIDC subject (set the OIDC provider's subject mode and the SCIM `externalId` mapping to the same value, for example the username), deactivation, reactivation, attribute updates, group membership changes and group-to-team-role mappings work. Deleting a user in authentik did not send a SCIM `DELETE` in our test (authentik's own task looked the deleted user up again and stopped). **Deactivate a person in authentik before deleting them**, so the portal suspends them at once. A deactivated person stays suspended; their credentials are kept rather than cleaned up, because clean-up follows only a SCIM `DELETE`. When authentik's automatic and manual syncs race to create the same group, the second create gets `409 uniqueness`; authentik logs that task as failed, and its other tasks still add the members to the one group.

Errors use the SCIM error schema (`status`, `scimType`, `detail`). Requests count against the per-credential request limit (`REQUESTS_PER_MINUTE`).

## Upgrading and limits

Migrations 51–56 are expand-only. The previous release keeps working against the expanded schema, and a status write by an older replica is treated as a manual decision, so it can't lift a directory restriction. Older replicas don't serve `/scim/v2` or apply the enrollment gate: **finish the rollout before enabling provisioning.** Any statement that writes `users.status` is recorded as a manual decision unless it also *changes* `manual_status` or `directory_standing` (the comparison is by value; migration 56's comment says "sets", which is narrower than the actual rule). The portal itself never writes `status` directly. An older replica's admin update writes the status even for a role-only change; on someone the directory has deactivated that also records a manual suspension, which an admin lifts by hand.

Not covered: real-time IdP sign-out (deactivation takes effect when the directory pushes it), remote token revocation at upstream providers, provisioning more than one directory, and identity correlation by any claim other than the OIDC subject. Interoperability is tested against RFC-shaped requests modelled on common clients; see [status](status.md) for the evidence behind this release.
