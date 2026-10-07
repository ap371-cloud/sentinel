/* Honest per-right enforcement labels.
 *
 * Mirrors the backend's policy receipt wording (documents/protection.py): a
 * right that the server itself gates is marked ENFORCED; a right that only the
 * controlled viewer can stop depends on that application running; and a copy
 * that has already left the system is never claimed to still be restrained by
 * kernel-level code — because that would be a fake security promise. */

export type EnforcementLevel = "ENFORCED" | "PARTIAL" | "APPLICATION DEPENDENT" | "NOT ENFORCEABLE";

export type RightHonesty = {
  right: string;
  level: EnforcementLevel;
  note: string;
};

export const ENFORCEMENT_LIMITATION =
  "POLICY ENFORCEMENT LIMITATION: once this copy leaves the controlled viewer, usage " +
  "restrictions travel with the file as labels, metadata and an embedded policy receipt " +
  "rather than as kernel-level enforcement. Attribution, signed audit evidence and " +
  "revocation of any further access still apply; blocking every screenshot or onward " +
  "copy on an unmanaged endpoint is APPLICATION DEPENDENT and is not claimed here.";

export const RIGHT_HONESTY: RightHonesty[] = [
  { right: "VIEW", level: "ENFORCED", note: "Server refuses the view before any session is issued." },
  { right: "DECRYPT", level: "ENFORCED", note: "Single-use authorisation nonce plus per-recipient watermark." },
  { right: "RENDER", level: "ENFORCED", note: "The server issues the page set only while RENDER stays allowed." },
  { right: "DOWNLOAD", level: "ENFORCED", note: "The server refuses the download path when the policy denies it." },
  { right: "EXPORT", level: "ENFORCED", note: "The export path is refused and renamed copies are flagged." },
  { right: "OFFLINE", level: "ENFORCED", note: "Offline use is capped by the server-issued time window." },
  { right: "SHARE", level: "ENFORCED", note: "Adds to the share register and is revocable; bytes already held can still be moved by hand." },
  { right: "RECOVER_KEY", level: "ENFORCED", note: "A separate privileged act the server denies by default." },
  { right: "EDIT", level: "APPLICATION DEPENDENT", note: "Held inside the controlled viewer; nothing restrains the file once it leaves." },
  { right: "COPY", level: "APPLICATION DEPENDENT", note: "Clipboard control depends on the viewer actually running." },
  { right: "PRINT", level: "APPLICATION DEPENDENT", note: "Blockable in the viewer; the print path runs outside this console." },
  { right: "FORWARD", level: "APPLICATION DEPENDENT", note: "Viewer-level only; a user can always move bytes another way." },
  { right: "SCREENSHOT", level: "NOT ENFORCEABLE", note: "A capture on an unmanaged endpoint cannot be blocked by this stack." },
];

export const ENFORCEMENT_TONE: Record<EnforcementLevel, "ok" | "warn" | "info" | "crit"> = {
  ENFORCED: "ok",
  PARTIAL: "warn",
  "APPLICATION DEPENDENT": "info",
  "NOT ENFORCEABLE": "crit",
};