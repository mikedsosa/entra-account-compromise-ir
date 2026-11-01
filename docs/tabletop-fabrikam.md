# Tabletop exercise: "Approve to continue" at Fabrikam

> **Fictional.** Fabrikam is Microsoft's sample company name. Every person,
> address, IP and time below is made up for training. IPs come from the
> documentation ranges in RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
> 203.0.113.0/24). Nothing here describes a real incident, and no results are
> claimed.

## Setup

- **Company:** Fabrikam, Inc., a mid-sized manufacturer using Microsoft 365
  and Entra ID P2, with the Sentinel Entra ID and Microsoft 365 connectors on.
- **Target:** `j.rivera@fabrikam.example`, accounts payable specialist. Not an
  admin.
- **Roles at the table:** incident lead, identity admin, Exchange admin, SOC
  analyst, help desk lead, communications/legal (optional).
- **Time:** 90 minutes. The facilitator reads each inject, the team says what
  it would do and which runbook step or query applies, and the scribe records
  decisions and gaps.

## Injects

### Inject 1 (T+0): MFA prompts at 06:10 local

The SOC gets an alert from query `03`. `j.rivera` has 9 MFA denials
(`ResultType` 500121) between 06:02 and 06:10 from 203.0.113.45. There is one
successful sign-in from the same IP at 06:11.

- What do you check first? (runbook 2.2, 2.3; query `11`)
- Is one successful sign-in after a run of denials enough to contain without
  reaching the user first? Who decides?
- ATT&CK: which technique is this? (T1621, then T1078.004)

### Inject 2 (T+15 min): the user calls the help desk

J. Rivera says "my phone kept buzzing, I hit approve so it would stop."

- What does the help desk say and do? What must it **not** do (for example,
  reset MFA over the phone without verifying the caller)?
- Do you run the containment steps now? In what order? (runbook 3.1–3.4)
- Who holds the Graph permissions and roles for each step today? Is that
  written down anywhere?

### Inject 3 (T+30 min): mailbox rule found

Query `06` returns a `New-InboxRule` event from 203.0.113.45 at 06:14. Its
`Parameters` include `MoveToFolder` (to "RSS Subscriptions") and conditions on
the words "invoice" and "payment".

- What is the attacker likely trying to do? (T1564.008; think about
  invoice/payment fraud)
- Which evidence do you capture before you remove the rule? (runbook 4.1)
- Who else needs to know (finance, vendors)?

### Inject 4 (T+45 min): an app nobody recognises

Query `07` shows `Consent to application` by `j.rivera` at 06:20 for an app
named "Fabrikam Docs Viewer", with delegated `Mail.Read` and
`offline_access`. ConsentType is `Principal`.

- Does disabling the account and revoking sessions stop this app? Why or why
  not? (runbook 4.2: existing access tokens stay valid until they expire)
- Disable or delete the service principal? (the app consent playbook says
  disable)
- How would you find other users who consented to the same app?

### Inject 5 (T+60 min): new MFA method

Query `08` shows `User registered security info` for `j.rivera` at 06:16,
initiated from 203.0.113.45.

- What does this mean for recovery? (runbook 4.3; T1556.006)
- How does the user re-enrol safely?

### Inject 6 (T+75 min): pressure to restore

The accounts payable manager needs J. Rivera working before a payment run at
noon.

- Which checks must pass before you re-enable the account? (runbook 5.1–5.3)
- What extra monitoring do you put in place, and for how long?

## Debrief questions

1. Which detection would have fired first in **our** tenant today? Have we
   actually tested it?
2. Could we have contained within 15 minutes of inject 1? What slowed us?
3. Would a Conditional Access setting have prevented this or made it harder
   (for example, number matching or phishing-resistant MFA, or blocking user
   consent to unverified apps)?
4. Did anyone need access they didn't have?
5. What will we change in the runbook, the queries or our policies? Who owns
   each change, and by when?

## Facilitator notes

- The intended "aha" moments: revoking sessions doesn't kill OAuth app access
  tokens straight away, and an attacker-added MFA method survives a password
  reset unless someone removes it.
- Don't score the team. Record gaps as action items.
