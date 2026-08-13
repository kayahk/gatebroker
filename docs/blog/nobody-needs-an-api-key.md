# Nobody needs an API key for your model gateway

How we gave developers governed access to approved models without issuing a single credential, using a component small enough to read in an afternoon.

## The moment you have a gateway, you have a key problem

Standing up a model gateway is the easy part. You pick one of the good open source proxies, point it at a provider, and within an afternoon you have a single endpoint that speaks the OpenAI API, routes to whichever models you have contracts for, and keeps the provider credentials in one place instead of scattered across every team that wanted to try something.

Then somebody asks the obvious question: who is allowed to use it?

Every quickstart answers that the same way. Issue a key. So you do. One for the platform team, one for the group experimenting with retrieval, one for the person who asked politely on Friday afternoon. A week later you have a spreadsheet, and the spreadsheet is the access control system.

We got about three weeks into that before it became clear it would not hold. Not because anything went wrong — nothing did — but because we could not answer questions we should have been able to answer instantly. Who is using the expensive model? Which keys belong to people who have left? If one of these leaked into a public repository tonight, which one would it be and what could it reach?

## What a key actually costs

It is worth being precise about why keys are the wrong primitive here, because "keys are bad" is the kind of received wisdom that stops people thinking.

A key carries no identity. It proves that whoever holds it once received it. It cannot tell you who is making a request, only which envelope the request arrived in, and the moment a key is shared between two people — which happens immediately, because it is a string and strings are easy to paste — even that much is gone.

A key outlives its owner. Somebody leaves, their accounts are disabled, their laptop is wiped, and the key they pasted into a personal project six months ago still works. Nothing about offboarding touches it, because nothing in your directory knows it exists.

A key cannot express an entitlement. "This group may use the two cheap models, that group may also use the expensive one" is a sentence about people and models. A key is a sentence about a string. You can approximate the policy by issuing one key per group and hoping nobody swaps them, which is exactly as robust as it sounds.

And a key is hard to revoke in practice, not because rotation is technically difficult but because you do not know who has it. Rotating means breaking an unknown number of working setups, so it gets deferred, and the deferral is how keys reach their second birthday.

Meanwhile every one of those problems is already solved elsewhere in your organization. You have an identity provider. It knows who people are, which groups they belong to, and it stops knowing them the day they leave. The gap is not that identity is hard. The gap is that the gateway does not speak it.

## The feature exists, one tier up

This is a well-understood gap, and the gateways know it. Look at almost any of them and you will find identity-aware access control on the roadmap or in the product — single sign-on, token-based authentication, roles mapped to teams, audit trails. It is usually in the commercial tier, priced per seat or per organization.

That is not a complaint, and I want to be careful here, because it would be easy to write this article as a way of dodging a bill. The vendors have it right: the organizations that ask for federated identity and audit retention are usually the organizations that can fund it, and building that properly is real work that deserves paying for. If you are at the scale where you need delegated team administration, provisioning that syncs with your directory, retention policies your auditor will accept, and somebody to call at two in the morning, buy it. You will not save money reproducing that, and this article is not for you.

But there is a band underneath that, and it is wider than the pricing pages suggest. Teams of twenty or fifty engineers. A platform group inside a mid-sized company. A research unit with real confidentiality obligations and a modest budget. Organizations that will never have hundreds of AI users but are still not comfortable with a shared secret in a spreadsheet, and cannot justify a five-figure line item for the one capability they actually need out of a governance suite.

We were in that band. What we needed was narrow: make model access follow the identity people already have, and let us say which groups may use which models. Not spend analytics, not retention policies, not delegated administration. One property.

The interesting question was how much code that property costs.

## What the exchange actually is

Strip away the product names and the situation is unusually simple.

The gateway needs exactly one thing to serve a request: a bearer credential it recognizes. It does not care who is behind it.

The caller already has something better than a credential. They have a signed token from your identity provider, which states who they are, which groups they belong to, when it was issued and when it stops being valid, and it is verifiable by anyone holding a public key.

So something has to sit between the two and do three things: check that the token is genuine, decide what that identity is allowed to reach, and forward the request using the gateway's own credential. The caller never holds the credential. The gateway never learns about identities.

That middle piece is smaller than it sounds. Verifying the token is signature validation against a published key set plus a handful of claim comparisons. Deciding what the identity may reach is a lookup from group membership to a list of model names. Forwarding is an HTTP call with one header replaced.

Written down that way, it stops looking like a product and starts looking like a component. So we built it. The service is under fifteen hundred lines of Python, with roughly three times that in tests, and it is called GateBroker.

## One policy, or nothing

The entitlement model is deliberately the smallest thing that expresses the sentence we wanted to say. A policy names the groups or roles it applies to, the models they may use, and the *name* of the credential the gateway will accept:

```json
{
  "policies": [
    {
      "id": "engineering",
      "group_ids": ["8f2c1e4a-..."],
      "allowed_models": ["gpt-4o-mini", "gpt-4o"],
      "key_ref": "ENGINEERING_GATEWAY_KEY",
      "priority": 10
    }
  ]
}
```

Two decisions in there matter more than they look.

The document contains `key_ref`, a name, and never a value. The broker resolves that name at request time from wherever the deployment put the secret — a mounted file, an environment variable, whatever your secret manager projects. This is what lets the policy document live in Git, be reviewed in a pull request, and be read by anyone, while the credential itself stays where credentials belong. A policy is a statement about who may do what, and statements about who may do what should be reviewable.

The other is that exactly one policy applies. The broker collects every policy matching the caller's groups, takes the highest priority, and if two are tied at the top it refuses the request. It would have been easy to union the allowed models, or to pick the first match, or to fall back to a default. All three are ways of guessing, and a guess in an authorization decision is a bug you find out about later. No match is a denial. An ambiguous match is a denial.

That is the pattern throughout. A token that fails any check is a denial. A model absent from the selected policy is a denial. A rate limiter that misbehaves fails closed rather than open. When we wrote the test suite, most of it ended up being refusals, which is the right shape: proving that a valid request gets through is the easy half.

## What crosses the boundary

Sitting in the request path means deciding what is allowed to pass, and this is where a proxy earns or loses its keep.

Client credentials do not pass. Whatever authorization, API key or routing headers the caller sent are dropped and replaced with the broker's own. A client cannot smuggle a credential of its choosing through to the gateway.

Client-claimed identity does not pass either. The OpenAI API has a `user` field, and the Anthropic one has `metadata.user_id`; both are ways for a caller to say who they are. The broker overwrites them with the verified subject from the token. This is the small detail that makes usage attribution mean something: the gateway is told who the caller *is*, not who they *said* they were.

Where that identity stops is the gateway's business, and stopping there is the right default. The gateway holds the provider credentials and calls the provider as itself, so internal user identifiers need not be handed to a third party at all.

Sizes are bounded, at a megabyte of request and ten of response, and streaming responses are relayed under the same cap rather than buffered. Nesting depth is bounded too, by an explicit scan rather than by catching the JSON parser's recursion error — that turned out to matter, because how deep the parser will go before failing changed between Python versions, and a limit that moves with your interpreter is not a limit.

And every request produces exactly one audit event: the route, the status, how long it took, the policy that was selected and the model that was requested. No tokens, no prompts, no request bodies, no subject identifiers, no IP addresses. That constraint is not squeamishness. The reason the broker is worth running is that nobody has to hold the provider credential; a log that quietly accumulates the interesting parts of every request has given that back for the sake of convenience.

## The part that runs on laptops

Half of this is a service. The other half is the awkward bit: developers run agents locally, and those agents want an API key in an environment variable. Solving the server side while everyone keeps a key in their shell profile would have missed the point entirely.

So there is a small CLI. It signs the user in through the device-code flow, keeps only the renewal state in the operating system credential store, and hands a short-lived token to exactly one child process:

```shell
gabro login
gabro run claude
```

The token exists in the environment of the spawned process and nowhere else. Not in a shell profile, not in the agent's configuration file, not in shell history. Some agents ignore the standard base-URL variables and want their own provider settings, so the CLI injects those too, which is unglamorous work but the difference between a boundary people use and one they route around.

Two details in there took a while to get right. The launcher profiles — saved commands, so you can type `gabro run claude` instead of the full invocation — are authenticated with a key in the credential store, because a profile names an executable, and without that check anything able to write the file could get a freshly minted token handed to a command of its choosing. And the CLI's tenant, client and gateway URL are compiled into the build rather than read from the environment, because if they were configurable a shell variable could redirect a fresh token to an endpoint of somebody else's choosing. A distribution sets them once and signs the result.

## Zero trust, concretely

That phrase has been worn smooth by marketing, so here is what it actually amounts to in this design.

There is no standing credential to steal. A developer's machine holds renewal state scoped to one resource, and a token that expires in an hour. The provider key never leaves the server side. If a laptop is lost, the response is to disable an account, not to rotate a secret and then wonder who else had it.

Every request is verified on its own merits. Not "this connection came from inside the network", not "this key was valid when we issued it", but: this token is signed by the provider we trust, it has not expired, it names this broker as its audience, and it carries a group that resolves to a policy that permits this model. Nothing is inferred from where the request came from.

Authority is the smallest thing that works. A group gets a list of models, not an account. Adding someone is directory membership; removing them is the same, and it takes effect on their next request rather than whenever somebody remembers the spreadsheet.

And the honest part: this is not a network control. The broker only constrains traffic that reaches it. A deployment that lets callers address the gateway directly has bypassed the whole thing by configuration, and no amount of code here prevents that. You need a network policy that lets the gateway accept traffic from the broker and nothing else. We say so in the deployment docs, twice, because it is the one thing that turns this from a control into a decoration.

## Who this is for

If you already run an open source gateway and hand out keys, and you have started to feel the spreadsheet, this is aimed squarely at you.

More specifically, it suits organizations with a real identity provider and a modest number of AI users. You need the directory — this is worthless without one — but you do not need to be big. It fits particularly well where confidentiality obligations are real but the budget is not enormous: research groups, engineering organizations inside larger non-software companies, anyone whose security review asks "who accessed which model" and will not accept "we issued four keys".

It also suits teams giving developers local coding agents, which is how we got here. Handing every engineer a gateway key so their editor can reach a model is the fastest way to lose track of credentials that has yet been invented.

It is not for you if you need spend analytics per team, provisioning that syncs with your directory, retention policies with a compliance certificate attached, or somebody to call when production traffic fails. Those are real requirements and this is not that product. It does one thing.

## What it cost us

I would rather read an honest account than a triumphant one, so here is the other side.

The rate limiter is process-local. It bounds one replica, and two replicas mean twice the limit because neither knows about the other. That is documented and there is an injection point for a shared limiter, but the bundled one is a courtesy rather than a control, and if you scale out having read only the README you will get a surprise.

Policies load once at startup, so changing an entitlement means restarting the pod. For a document that changes a few times a month this is fine and it keeps the request path free of file watching, but it is a rough edge and people do trip over it.

You own another hop. The broker sits between your developers and your gateway, which means it is now a thing that can be down. It is stateless and small, and it fails closed rather than open, but that is one more component on the path than you had yesterday.

The claim shapes lean towards one identity provider. It was built against Microsoft Entra first, so the defaults expect the claim names Entra uses. Other providers work — the demo runs against Keycloak, and the subject and scope claim names are configurable for exactly this reason — but that generality came from being forced to prove it, not from foresight, and I would not have found the assumptions without building the demo.

Group overage is refused rather than resolved. When a directory returns "this user has too many groups to list, ask me separately", the broker denies the request instead of making that call. That is the fail-closed choice, and for a user in a great many groups it is also an outage with a confusing cause.

## Would I do it again

Yes, and the reason is narrower than "we saved money".

We spent a while looking for a product that would give us identity-based model access, comparing tiers and working out which bundle contained the one capability we needed. That framing was the mistake. The thing we wanted was not a feature, it was a decision: which groups may use which models, and by what evidence. Once we wrote the decision down as a document, the code that enforces it turned out to be a signature check, a lookup, and a forwarded request.

That is not an argument against buying software. It is an argument for finding out how big the gap actually is before you go shopping, because the answer is sometimes a component rather than a platform, and a component you can read in an afternoon is a component you can reason about at three in the morning.

GateBroker is Apache-2.0 and there is a demo in the repository that runs the whole path — identity provider, broker, gateway, model — on a laptop with one command and no accounts to create. It asserts fourteen things, and over half of them are refusals.
