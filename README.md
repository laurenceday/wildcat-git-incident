# Wildcat Labs GitHub Incident: April 2026

On **2026-04-27 between 17:55 and 18:05 UTC**, an attacker used a Wildcat developer's stolen GitHub credentials to force-push obfuscated build-time and deploy-time RCE malware to the default branches of seven Wildcat repositories. The recovered malware used public blockchain explorers and RPC infrastructure as a dead-drop channel for second-stage payloads. In one variant, it also spawned a detached child `node` process to persist past the original parent process.

**NOTE: At no point during any of this incident were any user funds ever at risk. This incident did not affect any of our live services, the Wildcat Finance app, the live subgraph server, any deployed contracts, or any signers of the Wildcat Labs multisig.**

Two other Wildcat developers were exposed to the malware (had it on their systems) but do not appear to have actually been infected at any point.

Of the seven repositories, five were private repos for peripheral or experimental projects, and two were the public repositories for our V2 protocol contracts and our subgraph. From what we can tell, it is unlikely anyone external to Wildcat was infected, but we outline below how to tell if you are at risk.

The 3 impacted and potentially impacted devs have reformatted and rotated personal & Wildcat passwords. All sensitive secrets on Wildcat services have been rotated, but there is no sign any were used. The malicious commits have been rolled back and are unreachable from any of our existing branches (GitHub takedown pending).

## Attribution

Most likely actor: DPRK-linked, almost certainly the UNC5342 / "Contagious Interview" / Famous Chollima cluster (or an affiliate using the same infrastructure).

The smoking gun is sitting in our Indicators of Compromise (IoC) list provided below. The TRON address `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` appears verbatim in Ransom-ISAC's October 2025 [writeup on "Cross-Chain TxDataHiding"](https://ransom-isac.org/blog/cross-chain-txdatahiding-crypto-heist/) which they explicitly attribute to a DPRK-linked campaign investigated alongside Crystal Intelligence.

## Order Of Events

### Infection: GitHub Repositories Compromised

Following the system compromise of one of our developers, 7 Wildcat repos are compromised by force-pushes to their primary branches, containing RCE malware. The commits are designed to avoid suspicion by overwriting previous legitimate commits to sneak in the malicious code while reusing their author metadata, and placing the payload deep into a single line so that the GitHub UI file display will not show the code unless you look for it (notice that the diff overflows horizontally).

### Red Flag: Wallet Drain
The compromised Wildcat developer subsequently had his personal wallet drained for ~7,000 USDC, via a bare `transfer` rather than a `transferFrom`.

### Immediate Response: Post-Drain Security Tightening
After the drain, we performed a broad review of our security posture on GitHub and Vercel, looking to reduce the blast radius of a single compromised user.

We removed admin roles from people who didn't need them, added stricter branch-protection rules (more required reviews, more repos covered), tightened org workflow settings (what it was possible for CI to do).

## Discovery
The attack was discovered shortly thereafter during development of `analytics-app`. A developer was working with an AI agent that maintains external forks of Wildcat repositories. When the agent went to make several PRs from its fork back to the upstream repository, it noticed that the upstream HEAD matched a commit already present in the fork except for a different hash and a much newer date. That anomaly kicked off an investigation that surfaced six other affected repositories, all stemming from force-push commits in a roughly 10-minute window and all carrying similar payloads.

## Impact
**5 private** and **2 public** repositories affected.

| Repository         | Description                                              | File                                      | Visibility | Injection                                                                                                   | Impact                                                                                           |     |
| ------------------ | -------------------------------------------------------- | ----------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | --- |
| `tg-bot`           | Wildcat Telegram bot for market notifications            | Payload injected into `src/index.ts`      | Private    | Running the service                                                                                         | Dev machine possibly compromised. Live service was not impacted.                                 |     |
| `wildcat-sentinel` | Service to monitor markets for unpaid withdrawal batches | Payload injected into `src/index.ts`      | Private    | Running the service                                                                                         | Dev machine possibly compromised. Live service not impacted.                                     |     |
| `analytics-app`    | New analytics UI for Wildcat                             | Payload injected into `next.config.mjs`   | Private    | Running or building the app                                                                                 | Ran on Vercel environment with 0 secrets. Output bundle unaffected.                              |     |
| `<redacted>`       | Private internal Hardhat-enabled repository              | Payload injected into `hardhat.config.ts` | Private    | Required either an explicit `npx hardhat` command or having the Nomic  Hardhat extension installed and open | None                                                                                             |     |
| `<redacted>-app`   | Private internal Next.js application                     | Payload injected into `next.config.mjs`   | Private    | Running or building the app                                                                                 | Ran on Vercel environment with some non-sensitive test-server secrets. Output bundle unaffected. |     |
| `v2-protocol`      | Wildcat's V2 protocol smart contracts.                   | Payload injected into `hardhat.config.ts` | Public     | Required either an explicit `npx hardhat` command or having the Nomic  Hardhat extension installed and open | Dev machine possibly compromised. No contracts deployed on bad versions.                         |     |
| `subgraph`         | Wildcat's subgraph indexer code.                         | Payload injected into `scripts/deploy.js` | Public     | Required running the subgraph deploy script with valid args (to not throw before the malware injection).    | None                                                                                             |     |

### Investigation

After finding the commits, we began looking for any signs of unusual activity by the developers' known compromised account, any credentials they would've had on their machine (and thus were compromised), and signs of the malware on our other devs' machines.

We checked:

* **All other pushes by the compromised account** to any of our repos, particularly wildcat-app-v2. Other than the force-pushes, we only found legitimate work they were doing.
* **For similar force-pushes** to the developers' personal repos, we found one additional malware force-push to a personal project they had: no one else was using it at the time so no further risk of compromise. They've since rolled it back.
* **The GitHub audit logs across the org**. Found three rejected force pushes from the compromised account, blocked by branch protection we already had in place. Two to `wildcat-app-v2`, one to `wildcat.ts`.
* **The CI on compromised repos**: Only two had any workflows, which were simple lint / test runs, and both failed. No build caches, no secrets, no changes to workflows/hooks/actions.
* **Org-wide secrets, workflows, actions, apps, oauth apps**. Nothing unusual except a deprecated app that we removed.
* **Vercel build logs**. Found that `<redacted>-app` and `analytics-app` did execute the malware, but the output files were identical and these apps had no sensitive secrets. These had already been rolled back in the initial mitigation by the time we checked this.
* **Vercel team activity**. Also nothing unusual beyond confirmation the apps with the bad versions did deploy.
* **Supabase logs**. We looked for edits to the database used by the main Wildcat app. Since the compromised dev was on our Supabase team, we wanted to make sure the attack hadn't done anything to the borrower profiles (which would've been the extent of damage that could have been done). No such activity.

### Impact to Wildcat Labs

No live services were impacted, however, `<redacted>-app` and `analytics-app` ran Vercel deployments against the infected commits, causing them to run the malware during compilation. Neither had their bundles tampered with. `analytics-app` had zero secrets at all, and `<redacted>-app` had a few test environment secrets, none of which were sensitive.

All developer machines that had any possible exposure to the malware have been treated as if compromised and reimaged out of abundance of caution. All secrets that the compromised developers accounts had access to have been rotated, and the affected Vercel apps were rolled back to their pre-attack commits.

### Downstream Impact

Of the affected repos, the two public ones are:
- `wildcat-finance/v2-protocol`
- `wildcat-finance/subgraph`

We don't believe that anyone outside of Wildcat had pulled either of the compromised repositories in this timeframe based on the traffic stats we can see (although those stats are not very detailed), but if you pulled `wildcat-finance/v2-protocol` or `wildcat-finance/subgraph` after 2026-04-27, you should act as if your system and all credentials on it are potentially compromised to be safe.

Of the compromised repositories, the two public ones were among the least likely to infect a typical developer due to the unique circumstances required to trigger the malware.

The malicious code in `v2-protocol` was added to `hardhat.config.ts`, but this repo is a Foundry project. The hardhat config was added roughly two years ago to make the vscode extension `NomicFoundation.hardhat-solidity` support syntax highlighting and linting when our IDEs had issues with other configurations. To have the malware injected, you would have needed to first install the node packages, then either manually run a hardhat command or use some other tool which does so automatically (such as that vscode extension).

In `subgraph`, the attack was added to the end of the deploy script. This only runs when attempting to deploy the subgraph, and only reaches the RCE if the deployment is successful, as the script would abort otherwise.

Two additional points are worth calling out for teams evaluating comparable blast radii in their own environments:

- Only two affected repositories had GitHub Actions workflows at all.
- In both of those cases, the workflow runs triggered by the malicious pushes failed, and the repositories did not have meaningful GitHub Actions secrets configured.

For Wildcat, that meant the more important credential-exposure question was the deploy/build platform layer rather than GitHub Actions itself.

## Lessons / Recommendations

### What We Learned

We hadn't enabled some GitHub security features we should have:

- Commit signatures weren't required everywhere,
- Branch protection rules were only enabled selectively on high-value repos,
- Force-pushes weren't disabled on all main branches, and
- We had no Enterprise plan, so our audit logs were fairly limited and we needed to use the GitHub API directly to retrieve historical events.

Even with the changes that should prevent similar force-push issues, going forward we are now using a git hook (`./reference-transaction`) that surfaces any history overwrites more visibly (with block-by-default), but still keeps the experience for normal merging painless.

### Positive Takeaways

Relative to our teams' combined past experiences with security incidents, this one was much easier and faster to investigate and mitigate thanks to AI agents. We didn't need to figure out how to query the GitHub API for the compromised account's pushes, manually decode every layer of the exploit code, or figure out the right filters for the audit logs (once we knew what to look for). That automation let us fairly quickly step through what happened, how exposed we were and what needed to change.

Within about an hour of finding the malware, we had a good grasp of what had happened: which account had been compromised, how the attack worked, and which commits and repositories had been affected.

Since Wildcat Labs has essentially zero control over the protocol (aside from the SphereX security configuration), there was never any risk of the protocol itself being attacked.

## Recommendations

Here are some immediate recommendations we can make to any other organization that wishes to improve their security posture on GitHub.

### Basics
Here are some things that take nearly no effort, add very little developer friction, and likely would have stopped this attack or let us spot it sooner:

* **Enable branch protection rules everywhere.** This does not need to be especially inconvenient; simply requiring that the default branch be updated through a pull request would have likely stopped this particular attack, as shown by the attacker immediately backing off when wildcat-app-v2 didn't let them force push despite it being by far the most valuable target. There was no attempt at doing the same kind of attack on a feature branch pre-merge, no sophisticated attacks at all really beyond the quick-fire round of force pushes.

* **Require commit signatures everywhere.** It doesn't stop an attack obviously, but in this case, if the attackers had needed to rewrite someone else's commit as one made by the compromised account, it would have been more likely that our other developers would have caught it. And given their pattern of giving up quickly after failing to force push, it may have even stopped the attack.

* **Make your git config display force-pushes loudly.** Branch protection is the main control, but have a backup that even the admin can't override, so the developer's system will recognize a weird history change and surface it. We'll share the hook we're using going forward below.

* **Know where your secrets live and how to change them**. Write internal runbooks that answer "if something happens, how do we rotate all of the keys for <service> quickly?" It sounds trivial, and we figured it out fairly quickly, but it still took some time to identify everything that needed rotation, where we should go to reset it, and verify we didn't miss anything. Takes half an hour one time and would have saved us some time we could have spent on executing the response.

### Advanced

* **Automated code reviews** - Whatever your opinion of AI coding agents, it feels pretty clear that if we had them automatically reviewing our code (on every commit to a main branch or periodically reviewing the recent commits) this would have been caught almost instantly. We subsequently invested significantly into configuring this in a way that gives us very visible warnings for actual problems and avoids wasting our time with false positives.

* **Automated notice of GitHub rejections** - Even the very limited free GitHub plan did have the push rejections from the compromised account pushing to `wildcat-app-v2` and `wildcat.ts` (which the attacker gave up on after three attempts), but we didn't know about it.

## Exploit Analysis

Across the affected repositories, the attacker hid the payload in files that are naturally executed during local development, build, deployment, or service startup:

- `next.config.mjs` in Next.js applications
- `hardhat.config.ts` in Hardhat-enabled repositories
- `src/index.ts` in long-running Node services
- `scripts/deploy.js` in the subgraph deployment path

The surrounding diffs were usually copied from legitimate historical commits. The malicious delta was typically confined to a single execution-path file, often as one appended line at the end of the file.

For `v2-protocol` (a Hardhat/Foundry contracts repo with no Next.js config), the target was `hardhat.config.ts`, which suggests deliberate manual adaptation of the implant to that repository rather than a purely automated Next.js-focused workflow.

### Loader Behavior

The recovered first-stage loader, when the affected file was imported or executed by Node:

1. Sets a global marker such as `global['_V']='5-3-332'` or `global.i='5-3-332'` to deduplicate execution.
2. Fetches the latest transaction from a hardcoded TRON account via `api.trongrid.io`.
3. Uses the returned data to derive a BSC transaction hash, with an Aptos account used as a fallback source in the recovered Hardhat variant.
4. Queries BSC public RPC endpoints such as `bsc-dataseed.binance.org` or `bsc-rpc.publicnode.com` for that transaction.
5. Extracts an encoded payload from the transaction input.
6. XOR-decrypts the extracted bytes with a hardcoded key.
7. **`eval`s the result** in the current Node process.
8. Repeats the process with a second hardcoded set of account / transaction / key material.
9. In the recovered Hardhat-style loader, **spawns `node -e ...` as a detached child process** so the second stage can survive after the original command exits.

The stage-two payload was not embedded directly in the repository. Instead, the first stage pulled it dynamically from attacker-controlled data published through public blockchain-accessible infrastructure. That design gave the attacker the ability to rotate stage two without making further repository changes.

Captured stage-two samples contained exfiltration and backdoor behavior, including theft of local credentials, wallet material, and browser-session data.

### Obfuscation

The observed first-stage loaders used multiple layers of static obfuscation:

- a base64-decoded bootstrap wrapped in `eval(...)`
- string-table and token-substitution patterns such as `oWN(5586)`
- custom string-shuffling and token-replacement functions such as `lyR`

All three stages were deobfuscated using hand-written safe scripts (pure string operations, no `eval` / `Function` / `spawn`). No instance of the obfuscated code was ever executed during analysis.

## Indicator of Compromise (IoC) Fingerprints

The checks below are intended to be portable for third parties. They are read-only local checks and do not require building or executing the affected projects. This list is intentionally limited to the highest-signal checks.

### High-Confidence Repository iIndicators

If any of the following commit SHAs are reachable in a local clone, that system should be investigated immediately:

```text
e68f6379a9989801d1028bafc8ef86210a6b0446
44c62dd5d9b4cd61da2ce69a8b0e7572e497e19f
54e35e0c1aa1e9f4cabcf86ac3cd68e9c119ae61
cab0e9f851de02a486e6213b5dda2c2008bafb89
0fa96616c3ccc2f586b028162746fb17bacc509c
436f563321cbe17ec7134e1d35c410b48086a73a
6f7a23dbbe5ba59e8b29ab702c7fd7dfe74d84cb
b4494487236760311c5eb9545bf0db0ab246bb6a
```

Rejected but still useful for hunting in object databases:

```text
7628c1ee4a23529d6cba5554e39f8c8b88275de1
cbf07fcfa441ef9b9d9eeff83633cde96477c4f1
128d7deb031daae93c739412810a0e42f8f2d4de
```

Quick check inside local clones:

```bash
git cat-file -e <sha>^{commit} && echo "present"
```

Interpretation:

- If the malicious SHA was ever checked out, built, or run, treat the host as compromised.
- If the SHA exists only in remote-tracking refs or as an orphaned object, the risk is lower, but the host still needs review.

### High-Confidence File-Content Indicators

These strings are strong first-stage loader indicators and are suitable for file-content scanning:

```text
global.i='5-3-332'
global['_V']='5-3-332'
oWN(5586)
eval("global['_V']='5-3-332';"+atob(
createRequire(import.meta.url)
child_process
spawn("node",["-e",
```

Recommended search:

```bash
rg -n -S "5-3-332|oWN\\(5586\\)|eval\\(\"global\\['_V'\\]|createRequire\\(import\\.meta\\.url\\)|spawn\\(\" ~/code
```

`createRequire(import.meta.url)` by itself is not malicious. It should be treated as suspicious only when correlated with one of the stronger markers above.

### Network And Blockchain Dead-Drop Indicators

The first-stage loaders fetched stage-two material from public blockchain or RPC infrastructure. The following values are suitable for proxy, DNS, EDR, shell-history, or code searches.

Hosts:

```text
api.trongrid.io
fullnode.mainnet.aptoslabs.com
bsc-dataseed.binance.org
bsc-rpc.publicnode.com
```

Hardcoded account or transaction values recovered from the loaders:

```text
TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP
TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG
0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e
0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3
```

Hardcoded XOR keys from the decoded loader:
- 2[gWfGj;<:-93Z^C

```text
m6:tTh^D)cBz?NM]
```

### Code, Shell History, And Log Search:

```bash
rg -n -S "api.trongrid.io|aptoslabs.com|bsc-dataseed.binance.org|bsc-rpc.publicnode.com|TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG"
```

### Runtime And Persistence Indicators

A positive match for a detached `node -e` process should be treated as an active incident:

```bash
ps -ef | grep -E "node[[:space:]]+-e|global\\[.?['_V']" | grep -v grep
```

### Trigger Conditions

These indicators matter most if the affected repository was actually executed through one of the relevant entry points:

- `next.config.mjs`: `next dev`, `next build`, or any tool that imports the Next.js config
- `hardhat.config.ts`: `npx hardhat ...` or tools and IDE extensions that invoke Hardhat automatically
- `src/index.ts`: directly running the service
- `scripts/deploy.js`: invoking the subgraph deployment path successfully enough to reach the malicious append

### Practical Interpretation

- Positive git-object hit plus evidence the commit was checked out or built: treat the machine as compromised.
- Positive file-content hit in a working tree: treat the repository and host as compromised until proven otherwise.
- Positive process hit: isolate the host immediately.
- Only remote-tracking or orphaned git-object hits, with no file or process hits: lower risk, but still rotate credentials and clean local git object stores

## Production Impact Verification

Because part of the malware executed during builds, we explicitly checked whether the deployed user-facing output had been modified.

- We compared the affected Vercel build outputs against known-good outputs and found that the relevant files had identical sizes and hashes.
- Clean redeploys were triggered from known-good source after rollback.
- We found no evidence that attacker code had been propagated into live user-facing application bundles.

That distinction matters for similar incidents: build-time RCE does not automatically imply runtime bundle tampering, but it should never be assumed absent verification.
