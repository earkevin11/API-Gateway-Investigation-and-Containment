# API-Gateway-Investigation-and-Containment

# Investigating and Containing Attacks on API Gateways

An incident response guide for AWS API Gateway, with Azure API Management (APIM) equivalents.

New to API gateways? Read `API_Gateway_Fundamentals_README.md` first. Terms such as route, stage, authorizer, and API key are defined there.

---

## Table of contents

1. [The investigation at a glance](#1-the-investigation-at-a-glance)
2. [Two ways attackers go after a gateway](#2-two-ways-attackers-go-after-a-gateway)
3. [Check your evidence sources first](#3-check-your-evidence-sources-first)
4. [Indicators of attack and compromise](#4-indicators-of-attack-and-compromise)
5. [Questions to answer during the investigation](#5-questions-to-answer-during-the-investigation)
6. [Investigation queries](#6-investigation-queries)
7. [Deciding when to contain](#7-deciding-when-to-contain)
8. [Containment ladder](#8-containment-ladder)
9. [Recovery](#9-recovery)
10. [Practice scenarios](#10-practice-scenarios)

---

## 1. The investigation at a glance

| Step | Goal | Section |
| --- | --- | --- |
| 1 | Classify the attack: through the API, against its configuration, or both | [2](#2-two-ways-attackers-go-after-a-gateway) |
| 2 | Confirm which logs you have and where your blind spots are | [3](#3-check-your-evidence-sources-first) |
| 3 | Look for indicators and separate attempts from successes | [4](#4-indicators-of-attack-and-compromise), [6](#6-investigation-queries) |
| 4 | Answer the scoping questions: who, what, how much, still active? | [5](#5-questions-to-answer-during-the-investigation) |
| 5 | Decide whether and how hard to contain | [7](#7-deciding-when-to-contain) |
| 6 | **Preserve config**, then contain at the narrowest scope that works | [8](#8-containment-ladder) |
| 7 | Rebuild from known-good config and add detections | [9](#9-recovery) |

---

## 2. Two ways attackers go after a gateway

| | Through the API (data plane) | Against the API's configuration (control plane) |
| --- | --- | --- |
| **In plain words** | The attacker acts like a client and sends requests | The attacker logs into AWS and changes how the API works |
| **What they need** | Just the API's URL, sometimes a stolen key or token | Compromised AWS credentials with API Gateway permissions |
| **Examples** | Password guessing, scraping data, injection, flooding | Removing authentication, redirecting the backend, creating keys, turning off logs |
| **Evidence** | Access logs, WAF logs, backend logs | **CloudTrail** |
| **Azure equivalent evidence** | `ApiManagementGatewayLogs` | Azure Activity Log |
| **What it means** | The API is being abused | **An identity is compromised.** Contain that identity too, or the attacker can simply redeploy the API. |

---

## 3. Check your evidence sources first

Several important logs are **off by default**. Find out early what you have, because missing logs define your blind spot.

| Log | On by default? | What it tells you | Azure equivalent |
| --- | --- | --- | --- |
| CloudTrail management events | Yes, 90-day event history | Who changed the API and when | Activity Log |
| Access logs | **No**, enabled per stage | Each request: caller IP, route, status, response size | `ApiManagementGatewayLogs` |
| Execution logs | **No** | Step-by-step request handling, authorizer results | APIM diagnostics, Application Insights |
| WAF logs | **No** | Which requests were blocked and why | Front Door / App Gateway WAF logs |
| Lambda logs | Usually yes | What the backend did with each request | Function / App Service logs |
| CloudWatch metrics | Yes | Totals of requests, 4xx, 5xx, latency | Azure Monitor metrics |

### Recommended access log format

Turn this on before you need it. Each field answers an investigation question.

```json
{ "requestId":"$context.requestId", "ip":"$context.identity.sourceIp",
  "userAgent":"$context.identity.userAgent", "time":"$context.requestTime",
  "method":"$context.httpMethod", "path":"$context.resourcePath",
  "status":"$context.status", "responseLength":"$context.responseLength",
  "apiKeyId":"$context.identity.apiKeyId", "principal":"$context.authorizer.principalId",
  "integrationStatus":"$context.integration.status", "latency":"$context.responseLatency" }
```

---

## 4. Indicators of attack and compromise

- **Indicator of attack (IOA):** someone is trying. Example: hundreds of failed logins.
- **Indicator of compromise (IOC):** someone succeeded. Example: failed logins followed by successful ones from the same IP.

### Through the API (access logs, WAF logs)

| What you see | What it likely means | IOA or IOC |
| --- | --- | --- |
| Many 401/403 errors from a few IPs | Password or token guessing | IOA |
| Many 404s on paths like `/admin`, `/.env`, `/backup` | Attacker probing for hidden routes | IOA |
| Requests for `/claims/1`, `/claims/2`, `/claims/3`... | Walking through record IDs to scrape data | IOA, or IOC if they return 200 |
| `' OR 1=1`, `<script>`, `../` in requests | Injection attempts | IOA |
| 429 spikes or traffic far above normal | Flooding or scraping | IOA |
| User agents like `python-requests`, `curl`, or blank | Automated scripts, not a real app | IOA |
| Calls from new countries, Tor, or cloud hosting providers | Unusual sources worth checking | IOA |
| A run of 401s, then 200s from the same IP | Guessing worked | **IOC** |
| One caller receiving many 200s with large responses | Data being pulled out | **IOC** |
| One API key used from many IPs or countries | Key was stolen | **IOC** |
| 5xx errors after strange input, then unusual backend activity | Exploit worked | **IOC** |

### Against the configuration (CloudTrail)

Any of these by someone other than your deployment pipeline, outside a change window, or from an unusual IP is a red flag.

| CloudTrail event | Plain-English meaning | Why it's dangerous |
| --- | --- | --- |
| `UpdateMethod` / `PutMethod` with `authorizationType: NONE` | Login check removed from a route | Anyone can now call the backend |
| `UpdateAuthorizer`, `DeleteAuthorizer` | Login check changed or deleted | Could now accept any token |
| `UpdateIntegration`, `PutIntegration` | Backend target changed | Traffic and data can be redirected to the attacker |
| `UpdateRestApiPolicy` | Network restrictions changed | API may now be open to the whole internet |
| `CreateDeployment`, `CreateStage` | Changes pushed live, or a new stage created | Attacker's changes are now active |
| `UpdateStage` | Stage settings changed | Can turn off logging or throttling |
| `CreateApiKey`, `CreateUsagePlanKey` | New key issued | Attacker gives themselves ongoing access |
| `UpdateFunctionCode` (Lambda) | Backend code replaced | Backend now does what the attacker wants |
| `DisassociateWebACL` (WAF) | WAF removed from the API | Attack filtering turned off |
| `DeleteStage`, `DeleteRestApi` | API removed | Destruction or covering tracks |

---

## 5. Questions to answer during the investigation

| Area | Question | Where the answer is |
| --- | --- | --- |
| Scope | Which API, stage, and routes are affected? What data sits behind them (PHI, PII)? | API config, tags, data owners |
| Scope | What else shares this gateway or domain? Who breaks if we contain? | Custom domain mappings, APIM products, app owners |
| Caller | Which IPs, API keys, or user identities are involved? | Access logs (`ip`, `apiKeyId`, `principal`) |
| Success | Did any attempt succeed, and how much data left? | Access logs (`status`, `responseLength`) |
| Configuration | Was the API changed? By whom, when, and from where? | CloudTrail `userIdentity`, `sourceIPAddress` |
| Identity | Is the identity that changed the API compromised? What else did it do? | CloudTrail across all services |
| Backend | Did the backend do anything unusual, such as writing to S3 or creating resources? | Lambda logs, CloudTrail |
| Blind spots | Were logs or the WAF turned off, and for how long? | `UpdateStage`, `DisassociateWebACL` events |
| Urgency | Is the attacker active right now? | Timestamp of the most recent events |
| Approval | Who can approve containment that breaks production? | Incident commander, app owner |

---

## 6. Investigation queries

Adjust table names and log field names to match your environment.

| Goal | Query below |
| --- | --- |
| Find configuration changes | A |
| Find top failing callers | B |
| Find successful guessing | C |
| Find possible data theft | D |
| Check the API's current state | E |
| Azure APIM equivalents | F, G |

**A. CloudTrail via Athena: all API Gateway changes in the last 14 days**

```sql
SELECT eventtime, eventname, useridentity.arn, sourceipaddress, requestparameters, errorcode
FROM cloudtrail_logs
WHERE eventsource = 'apigateway.amazonaws.com'
  AND eventname NOT LIKE 'Get%'
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '14' day
ORDER BY eventtime DESC;
```

**B. CloudWatch Logs Insights: top failing callers**

```
fields @timestamp, ip, status, path
| filter status >= 400
| stats count(*) as errors by ip, status
| sort errors desc
| limit 25
```

**C. CloudWatch Logs Insights: failures followed by successes**

```
fields ip, status
| stats sum(status = 401 or status = 403) as fails, sum(status = 200) as successes by ip
| filter fails > 50 and successes > 0
| sort fails desc
```

**D. CloudWatch Logs Insights: callers receiving the most data**

```
fields ip, responseLength
| filter status = 200
| stats count(*) as calls, sum(responseLength) as bytes by ip
| sort bytes desc
| limit 25
```

**E. AWS CLI: current state of the API**

```bash
aws apigateway get-stages --rest-api-id <id>
aws apigateway get-resources --rest-api-id <id> --embed methods   # look for authorizationType NONE
aws apigateway get-authorizers --rest-api-id <id>
aws apigateway get-rest-api --rest-api-id <id>                     # includes the resource policy
aws apigateway get-api-keys
```

**F. Azure APIM (KQL): top failing callers**

```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(24h) and ResponseCode >= 400
| summarize Failures = count() by CallerIpAddress, ResponseCode, ApiId
| order by Failures desc
```

**G. Azure APIM (KQL): configuration changes**

```kql
AzureActivity
| where ResourceProviderValue =~ "MICROSOFT.APIMANAGEMENT"
| where OperationNameValue !endswith "READ"
| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue, CallerIpAddress
```

---

## 7. Deciding when to contain

| What you found | Decision |
| --- | --- |
| Only failed attempts, all blocked, nothing successful | Monitor. Add WAF blocks. No disruptive action. |
| An attacker got data or unauthorized access | **Contain now**, starting at tier 1 |
| API configuration was changed by an unexpected identity | **Contain the identity now**, then restore the configuration |
| Active theft of sensitive data, or the backend is destroying data | **Contain immediately** at tier 2 or 3 with incident commander approval |
| The gateway or domain is shared with other apps | Contain at the narrowest scope (IP, key, route) before touching the stage or domain |

---

## 8. Containment ladder

**Rule:** preserve evidence first, then start at the lowest tier that stops the attack. Move up only if the attack continues.

| Tier | Action | What it does | Disruption | AWS how-to | Azure APIM equivalent |
| --- | --- | --- | --- | --- | --- |
| 0 | **Export each stage's config** | Saves routes, authorizers, backends, and resource policy as evidence and a rebuild blueprint | None (read-only) | Stage actions → Export → OpenAPI 3, JSON, with API Gateway extensions | Export the API as OpenAPI, or export the ARM/Bicep template |
| 0 | **Capture stage settings and logs** | Saves what the export may miss (throttling, logging, WAF, variables) | None | `aws apigateway get-stage`; export CloudWatch and CloudTrail | Export diagnostics and the Activity Log |
| 1 | Block attacker IPs | Stops known sources | Low | AWS WAF IP block rule | `ip-filter` policy or WAF rule |
| 1 | Disable a stolen API key | Cuts off that one caller | Low | `aws apigateway update-api-key --api-key <id> --patch-operations op=replace,path=/enabled,value=false` | Regenerate or suspend the subscription key |
| 1 | Contain the compromised identity | Stops further configuration changes | Low | Deactivate access keys, attach a deny-all policy, revoke role sessions | Disable the user and revoke sessions in Entra; remove APIM role assignments |
| 1 | Restore tampered configuration | Puts the authorizer and backend back | Low to medium | Fix the method or integration, then create a new deployment | Restore policy from source control |
| 2 | Resource policy deny | Allows only approved IPs or networks | Medium | Update the policy, **then redeploy the stage** or it won't take effect | `ip-filter` allowlist |
| 2 | Throttle the stage to zero | Stops all calls while keeping the configuration | Medium, outage for that stage | `aws apigateway update-stage` setting rate and burst limits to 0 | Policy that returns 403 |
| 2 | Stop the backend | Prevents damage even if calls get through | Medium | Set Lambda reserved concurrency to 0 | Stop the Function or App Service |
| 3 | Remove the custom domain mapping and disable the default URL | Public URLs stop reaching the API | High | Delete the base path mapping; disable the `execute-api` endpoint | Remove the API from its product or custom domain |
| 3 | **Delete the stage** | Removes the live endpoint completely | High | Stage actions → Delete stage | Delete the API or revision |

### Why the runbook exports before deleting

| Runbook step | Purpose | Note |
| --- | --- | --- |
| Section 1: Snapshot API Gateway configuration | Proves what the attacker changed, and lets you rebuild the stage exactly | Read-only, so it isn't actually disruptive despite the label |
| Section 2: Delete stage | Fastest way to shut the public door on that environment | Breaks every legitimate client and erases stage settings. The deployments survive, so the stage can be recreated from the snapshot. Try tier 2 first unless the attack is severe and active. |

### Common containment mistakes

| Mistake | Why it matters |
| --- | --- |
| Containing the API but not the identity behind configuration changes | The attacker redeploys within minutes |
| Changing the resource policy without redeploying | The change doesn't take effect |
| Blocking the custom domain but leaving the default `execute-api` URL open | The attacker switches to the default URL |
| Deleting the stage before exporting it | Evidence and the clean rebuild are lost |
| Containing a shared stage or domain without warning other owners | Unrelated apps go down |
| Ignoring the backend's own permissions | An attacker with stolen credentials can call Lambda or S3 directly, skipping the gateway |

---

## 9. Recovery

| Step | Action |
| --- | --- |
| 1 | Fix the root cause: add the missing authorizer, patch the code, rotate leaked keys and secrets |
| 2 | Rebuild from the exported snapshot or infrastructure-as-code, never from the attacker-modified version |
| 3 | Reduce the backend execution role to only what it needs |
| 4 | Turn on access logs, execution logs (errors), and WAF logging if they were off |
| 5 | Reopen traffic gradually: approved callers first, then normal limits |
| 6 | Add alerts for `authorizationType: NONE`, `UpdateIntegration`, `CreateApiKey`, and logging changes |
| 7 | Document the timeline, data exposure, and notification decisions (HIPAA, legal) |

---

## 10. Practice scenarios

Work through each one: what do you check, what do you conclude, and which tier do you start at?

| Scenario | What you see | Key question | Response |
| --- | --- | --- | --- |
| **Claim scraping** | One IP requests `/claims/1` through `/claims/40000`, all returning 200 | Does the backend check that the caller owns each claim? | WAF block (tier 1), fix the authorization logic, assess PHI exposure |
| **Leaked partner key** | Partner A's key used from 30 IPs in 6 countries | Was the key the only control? | Disable the key (tier 1), reissue securely, add token-based auth |
| **Authentication removed** | CloudTrail shows `UpdateMethod` set to `NONE` on `POST /upload`, then `CreateDeployment`, from an unknown IP at 1 a.m. | Whose credentials were used, and what else did they change? | Export (tier 0), contain the identity, restore the authorizer and redeploy (tier 1) |
| **Backend redirected** | `UpdateIntegration` points `/login` to an external URL | Were user passwords sent to the attacker? | Export, contain the identity, restore the integration, force password resets |
| **Backend used for destruction** | Public route with no authorizer drives a Lambda that overwrites S3 files | Is this ransomware? Are older S3 versions intact? | Throttle to zero or stop the Lambda (tier 2), block S3 writes, escalate to the ransomware playbook |
