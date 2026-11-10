# Auth0 agent features as evidence events

Each Auth0 feature for AI agents issues or brokers a token at a point an agent acts. This page names the evidence event each one produces, the members of the agent audit record's `principal` it fills, and where the record still has no place for what the feature carries. The `principal` member and the `identity_provider` term are described in [principal-identity.md](principal-identity.md). Every record below derives `identity_provider: auth0` from its issuer URL.

The provider's own log of the same issuance is a second account. `idp_log_witness/v1` in [agent-evidence-verify](https://github.com/probityai/probity/tree/main/packages/agent-evidence-verify) reconciles the two: a record whose principal has no matching issuance in the tenant log export is a finding.

## The map

| feature | evidence event | `principal` members filled | tenant log event | vectors |
|---|---|---|---|---|
| Auth for MCP | an MCP server permits a tool call under an access token it validated | `issuer`, `subject` (the user), `clientId` (the registered or metadata-document client), `audience` (the MCP server's resource identifier), `authMethod` (`none` for a public client, else its registered method), `source: jwt-access-token`, `tokenDigest`, `issuedAt`, `expiresAt`, `kid`, `key`, `keyThumbprint`, `jwksDigest` | `seacft` or `sertft` | needed: an audience that is a resource indicator, and a client id that is a URL |
| On-Behalf-Of Token Exchange | an MCP server exchanges the token it received for a token to a first-party API and calls it | as above, with `audience` the API; `subject` stays the user | `success_on_behalf_of_token_exchange`, with the actor chain in `details.actor` and the new token's `jti` in `details.access_token_jti` | needed: the record has no member for the `act` chain, so the agent that acted and every hop before it are not recorded |
| Agent as Principal | an agent-linked client acts under a token whose subject is the agent (client credentials), or whose `act` names the agent (login and exchange grants) | `subject` (the agent's `external_agent_id`, else its `agent_id`), `clientId`, `audience`, `authMethod`, `source: jwt-access-token`; the delegation's `subjectKind` is the agent for client credentials | `seccft`, `sertft` and the exchange events, each carrying `agent_id` and `external_agent_id` | needed: `sub_profile` and `client_profile` (entity types of the subject and the client) have no member |
| Token Vault | an agent obtains a third-party provider's access token for the user and calls that provider | for the Auth0 token that authorized the exchange: `subject`, `clientId`, `audience`, `source: jwt-access-token`; the third-party token is a second credential, issued by another provider | the exchange event for the Auth0 token; the third-party issuance is in that provider's log | needed: a record that binds the brokered credential's digest and issuer to the Auth0 principal that obtained it |
| Async Authorization (CIBA) | a user approves an agent's request out of band, then a token is issued for the approved action | `subject` (the approving user), `clientId`, `audience`, `source: jwt-access-token`, `issuedAt` at or after the approval | `ciba_exchange_succeeded`, with `details.transaction_linking_id` | needed: a binding between the approval's binding message and the decision's request digest |

## What the tenant log adds

Auth0 writes `agent_id` and `external_agent_id` into the tenant log entry for client credentials, refresh token and on-behalf-of exchange grants from agent-linked clients, and for standard logins by an agent-linked client. Those entries are exported in near real time by log streams. A record's `principal` and the log entry for its token name the same client and subject at the same time; when they do not, either the record or the log is wrong, and only a party holding both can say which.

## Sources

- Auth for MCP: <https://auth0.com/ai/docs/mcp/overview>
- On-Behalf-Of Token Exchange: <https://auth0.com/docs/api/authentication/on-behalf-of-token-exchange/get-token>
- Agent as Principal, identity in tokens and tenant logs: <https://auth0.com/docs/ai-agents-mcp/agent-as-principal/agent-identity-in-tokens>, <https://auth0.com/docs/ai-agents-mcp/agent-as-principal/tenant-logs>
- Token Vault: <https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault>
- Asynchronous authorization and CIBA: <https://auth0.com/ai/docs/intro/asynchronous-authorization>, <https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow>
- Tenant log event types and log streams: <https://auth0.com/docs/customize/log-streams/event-filters>, <https://auth0.com/docs/customize/log-streams>
