Update NetFast VPN first-attempt handling with a 24-hour re-apply deadline.

Required behavior:

1. On first confirmed VPN/proxy/tunnel attempt:
   - Do not immediately re-apply NetFast enforcement.
   - Pause/block the active challenge.
   - Show a blocking modal.
   - Tell the user VPN was detected.
   - Tell the user this is their first and final warning.
   - Tell the user they must disable the VPN and click “Re-apply protection” within 24 hours.
   - Start a 24-hour countdown timer.
   - Send warning violation to backend.
   - Do not resume challenge until protection is re-applied and validation passes.

2. If user clicks the button within 24 hours:
   - Re-run full NetFast lockdown.
   - Validate:
     - VPN disabled
     - DNS locked
     - DoH configured
     - browser DoH locked
     - firewall core locked
     - bypass resolvers blocked
     - restricted content blocked
   - If validation passes:
     - Resume challenge.
     - Keep VPN attempt count = 1.
   - If VPN is still active:
     - Do not resume.
     - Show message: “VPN is still active. Disable it before re-applying protection.”

3. If user does not re-apply within 24 hours:
   - Fail/end the challenge.
   - Send final violation to backend.
   - Mark reason:
     "VPN detected and protection was not re-applied within 24 hours."
   - Stop watchdog/network re-lockdown loops.
   - Remove NetFast enforcement.
   - Restore pre-NetFast system state from snapshot.
   - Mark deposit/refund status as non-refundable according to challenge terms.

4. On second confirmed VPN attempt:
   - Immediately fail the challenge.
   - No second warning.
   - Remove NetFast enforcement.
   - Restore pre-NetFast state.
   - Send final violation to backend.

First VPN warning modal:

Title:
"VPN Detected"

Body:
"NetFast detected a VPN/proxy tunnel. This is treated as a bypass attempt. This is your first and final warning.

Disable the VPN and re-apply protection within 24 hours to continue your challenge.

If you do not re-apply protection within 24 hours, your challenge will fail and your payment/deposit will not be refunded according to the challenge rules.

Another VPN/proxy attempt will immediately fail your challenge."

Button:
"I understand — Re-apply protection"

Secondary text:
"Protection will only be re-applied after you disable the VPN."

Backend payload for first attempt:

{
  vector: "unknown_vpn",
  severity: "critical",
  attemptCount: 1,
  actionTaken: "warning_issued_waiting_for_reapply",
  challengePaused: true,
  reapplyDeadlineAt: ISO_TIMESTAMP_24_HOURS_LATER,
  refundEligible: false_if_deadline_missed,
  challengeFailed: false
}

Backend payload if 24h deadline expires:

{
  vector: "unknown_vpn",
  severity: "critical",
  attemptCount: 1,
  actionTaken: "challenge_failed_reapply_deadline_expired",
  challengeFailed: true,
  refundEligible: false,
  enforcementRemoved: true,
  systemRestored: true,
  reason: "VPN detected and user did not re-apply protection within 24 hours."
}

Local state file:

data/vpn-warning-state.json

{
  userId,
  deviceId,
  challengeId,
  firstVpnDetectedAt,
  reapplyDeadlineAt,
  warningAcknowledged: boolean,
  reapplyClickedAt: null | ISO_TIMESTAMP,
  challengePaused: true,
  expired: boolean,
  resolved: boolean
}

Timer behavior:
- Timer must survive app restart.
- On app startup, check vpn-warning-state.json.
- If deadline expired and challenge is not resolved:
  - fail challenge
  - send final violation
  - restore system
- Backend is source of truth if available.
- Local state prevents app restart bypass.

Challenge state behavior:
- During the 24-hour warning window:
  status = "VPN warning — protection re-apply required"
  challengeActive = false
  challengePaused = true
  canContinue = false

After successful re-apply:
  status = "Protected"
  challengeActive = true
  challengePaused = false

After deadline expiry:
  status = "Challenge failed"
  challengeActive = false
  refundEligible = false

Restoration requirement:
On challenge failure due to second VPN attempt or 24-hour expiry:
- Stop watchdog/networkWatch/DNS health re-lock loops.
- Remove NetFast firewall rules.
- Remove NetFast browser policies.
- Restore adapter DNS from pre-lockdown snapshot.
- Restore Windows DoH from pre-lockdown snapshot.
- Remove NetFast hosts section.
- Remove NetFast NRPT rules.
- Restore tunnel state if snapshot exists.
- Do not re-apply lockdown again for the failed challenge.

Important safety:
- Do not delete unrelated firewall rules.
- Do not delete unrelated hosts entries.
- Do not reset all DNS blindly.
- Restore only what NetFast changed.
- If pre-lockdown snapshot is missing, remove only NetFast-created items and show restoration warning.

Do not modify unrelated MongoDB, Docker, WSL, auth, package versions, database models, or unrelated UI.
Give me full updated files, not snippets.impo