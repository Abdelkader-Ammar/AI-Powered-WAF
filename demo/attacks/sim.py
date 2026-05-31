"""Black-box attack simulator. Sends labelled requests to the WAF proxy and
records, per request, what we sent and what the WAF returned. It imports no WAF
code -- it only speaks HTTP. Every shot is tagged with its attack class and the
outcome we expect, and that label travels with the request (X-Demo-Label) so the
observer can show "what it is" beside "what the WAF did".

Distinct actors are presented via X-Forwarded-For (the demo orchestrator runs
with TRUST_XFORWARDED=true), so the attacker, the victim, and a clean user are
scored independently -- and a ban on one does not affect the others.

Usage:
    python sim.py warmup
    python sim.py scenario sqli_coraza [actor_ip]
    python sim.py storyline
"""
import asyncio
import json
import os
import sys
import time
import uuid

import httpx
import yaml

WAF = os.environ.get("WAF_URL", "http://localhost:8080")
HERE = os.path.dirname(os.path.abspath(__file__))

# Named actors -> the source IP each presents (via X-Forwarded-For). Each attack
# uses its OWN fresh IP so the dashboard shows a wide range of distinct entities
# and score trajectories, and so each RASP exploit actually fires (a banned actor
# is refused at the edge and never reaches the backend). The single exception is
# the deliberate "banned retry" step, which reuses the RCE attacker's IP.
ACTORS = {
    "clean":    "198.51.100.10",   # a well-behaved logged-in human
    "recon":    "203.0.113.40",
    "enum":     "203.0.113.41",
    "brute":    "203.0.113.42",
    "flooder":  "203.0.113.43",    # DDoS
    "scraper":  "203.0.113.44",
    "sqli":     "203.0.113.45",
    "xss":      "203.0.113.46",
    "rce":      "203.0.113.47",    # RASP A
    "webshell": "203.0.113.48",    # RASP A
    "lfi":      "203.0.113.49",    # RASP A
    "ssrf":     "203.0.113.50",    # RASP A
}


def actor_ip(actor: str) -> str:
    return ACTORS.get(actor, actor)  # allow a raw IP too


async def fire(client, scenario, shot, actor):
    demo_id = uuid.uuid4().hex[:12]
    h = dict(shot.get("headers") or {})
    h["X-Demo-Label"] = scenario
    h["X-Demo-Id"] = demo_id
    h["X-Forwarded-For"] = actor_ip(actor)
    body = shot.get("body", "")
    content = body.encode() if body else None
    if content and "content-type" not in {k.lower() for k in h}:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    t0 = time.time()
    try:
        r = await client.request(shot.get("method", "GET"), WAF + shot["path"],
                                 content=content, headers=h)
        status, rbody = r.status_code, _safe(r)
    except Exception as e:
        status, rbody = -1, {"_error": str(e)}
    return {
        "demo_id": demo_id, "scenario": scenario, "actor": actor,
        "expect_layer": shot.get("expect_layer"), "expect_decision": shot.get("expect_decision"),
        "status": status, "rtt_ms": round((time.time() - t0) * 1000, 1),
        "waf_body": rbody,
    }


def _safe(r):
    try:
        return r.json()
    except Exception:
        return {"_raw": r.text[:160]}


def load_scenarios():
    with open(os.path.join(HERE, "scenarios.yaml")) as f:
        return yaml.safe_load(f)


def expand(name):
    """Expand a scenario into its individual shots (honouring `repeat`)."""
    out = []
    for s in load_scenarios()[name]:
        s = dict(s)
        n = s.pop("repeat", 1)
        out.extend([s] * n)
    return out


# Default spacing between sequential requests, so an admin watching the dashboard
# can see decisions tick in one by one rather than all at once.
PACE = float(os.environ.get("DEMO_PACE", "0.25"))
STEP_PAUSE = float(os.environ.get("DEMO_STEP_PAUSE", "1.5"))


async def run_scenario(name, actor="scanner", concurrent=False, pace=PACE):
    shots = expand(name)
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        if concurrent:
            # A volumetric flood/burst must land inside the trust engine's ~1s
            # burst window, so these fire at once (a real flood is instantaneous).
            return list(await asyncio.gather(*(fire(client, name, s, actor) for s in shots)))
        out = []
        for i, s in enumerate(shots):
            if i and pace:
                await asyncio.sleep(pace)
            out.append(await fire(client, name, s, actor))
        return out


# ── reporting helpers ────────────────────────────────────────────────────────
def _why(res):
    """Human-readable 'why blocked' from the WAF's response body / status."""
    body = res["waf_body"]
    if isinstance(body, dict):
        if body.get("decision"):                 # gatekeeper verdict json
            return f"gatekeeper:{body['decision']}"
        if "error" in body:
            return str(body["error"])[:48]
    s = res["status"]
    return {403: "blocked", 401: "challenge/auth", 429: "rate-limited",
            200: "allowed", -1: "error"}.get(s, str(s))


def summarise(title, results):
    print(f"\n=== {title} ===")
    for r in results:
        verdict = "ALLOW" if 200 <= r["status"] < 400 else "STOP "
        print(f"  [{verdict}] {r['actor']:<9} {r['scenario']:<14} "
              f"HTTP {r['status']:<4} {r['rtt_ms']:>6}ms  why={_why(r)}")


# ── the comprehensive storyline ──────────────────────────────────────────────
async def run_storyline():
    print("#" * 70)
    print("#  AI-WAF storyline: every tier, multi-tier, and a banned-user retry")
    print("#  (paced so you can watch each phase land in the dashboard)")
    print("#" * 70)

    async def step(title, name, **kw):
        summarise(title, await run_scenario(name, **kw))
        await asyncio.sleep(STEP_PAUSE)   # let the dashboard refresh between phases

    # 1. A clean user builds trust -- everything allowed.
    await step("1. clean user browses (trust builds)", "benign_human", actor="clean")

    # 2. UEBA / Gatekeeper tier: behavioural attacks, each from its OWN fresh IP,
    #    landing in a DIFFERENT decision band so all four are visible:
    await step("2a. recon sweep   -> Trust Engine -> BLOCK", "recon_sweep", actor="recon")
    await step("2b. id enumeration-> Trust Engine (recon)", "id_enum", actor="enum")
    await step("2c. brute force   -> Trust Engine -> BLOCK", "brute_login", actor="brute")
    await step("2d. DDoS flood    -> Trust Engine hard-override -> BAN",
               "ddos_burst", actor="flooder", concurrent=True)
    # A single sensitive-endpoint probe: suspicious but unproven -> CHALLENGE (a
    # proof-of-work). Even its following benign requests are challenged until it
    # proves itself. Reliable at any pace (persistent signal, not a 1s burst).
    await step("2e. sensitive probe -> Trust Engine -> CHALLENGE (proof-of-work)",
               "sensitive_probe", actor="scraper")

    # 3. Payload attacks, each from its own IP. NOTE: this demo ships with the
    #    signature/ML front tiers PERMISSIVE (Coraza off, ML threshold 0.99) to
    #    spotlight the RASP, so these reach the backend instead of being blocked
    #    here. Enable Coraza / lower the threshold in Settings to see them blocked.
    await step("3a. SQLi payload  (front tiers permissive by default)", "sqli_coraza", actor="sqli")
    await step("3b. reflected XSS", "xss_reflected", actor="xss")

    # 4. RASP (Tier 2) channel A -- the real exploitation, EACH from a fresh IP so
    #    every detection fires. The backend runs under the RASP shim, so the
    #    dangerous syscall is refused INLINE and the entity's score craters to 0.
    await step("4a. RCE /ping;id    -> RASP A: posix_spawn refused + BAN", "rce_exec", actor="rce")
    await step("4b. webshell .php   -> RASP A: executable write refused + BAN", "webshell", actor="webshell")
    await step("4c. LFI /etc/passwd -> RASP A: open() refused + BAN", "lfi_read", actor="lfi")
    await step("4d. SSRF metadata   -> RASP A: connect() refused + BAN", "ssrf", actor="ssrf")

    # 5. THE PERSISTENCE SCENARIO (the one deliberate banned-IP case): the RCE
    #    attacker from 4a, now banned, retries a perfectly innocent request and is
    #    still refused at the Gatekeeper -- the ban sticks.
    await step("5. banned RCE attacker retries a BENIGN request -> still BANNED",
               "benign_human", actor="rce")

    # 6. Isolation proof: the clean user from step 1 is still fully trusted.
    await step("6. clean user is UNAFFECTED by the attacks", "benign_human", actor="clean")

    print("\nStoryline complete. Open the dashboard (:8082): the 'Confirmed")
    print("Exploitation' feed shows each RASP catch; click any row for the")
    print("full payload / syscall. Enable Coraza in Settings to add the front wall.")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    mode = sys.argv[1]
    if mode == "storyline":
        asyncio.run(run_storyline())
    elif mode == "warmup":
        summarise("warmup", asyncio.run(run_scenario("benign_human", "clean")))
    elif mode == "scenario" and len(sys.argv) >= 3:
        actor = sys.argv[3] if len(sys.argv) >= 4 else "scanner"
        summarise(sys.argv[2], asyncio.run(run_scenario(sys.argv[2], actor)))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
