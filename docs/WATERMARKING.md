# Forensic watermark engine

The core of the system. Everything else is bookkeeping; this is what makes a leaked copy traceable.

---

## 1. Design constraints

The problem statement requires a mark that is:

- **unique per decryption session** — two sessions for the same recipient must differ;
- **invisible** — copies must remain visually equivalent;
- **recoverable** — from a copy that has been saved, compressed, rescaled or screenshotted;
- **cryptographically bound** — provably tied to that session, not merely associated;
- **honest** — a failure to recover must be reported as a failure.

### What was rejected, and why

| Approach | Why it fails |
|---|---|
| Visible text overlay (`"USER-001"`) | Violates "invisible" outright |
| PDF metadata or custom field | Stripped by any re-save. Provides no robustness at all |
| LSB steganography in PDF structure | Dies on re-save, which is the first thing a leak goes through |
| Plaintext recipient id in the payload | Leaks identity to anyone holding the copy, and is not tamper-evident |
| Embedding only in a fingerprint or serial | Removed by printing, scanning or screenshotting |
| Reporting FOUND unconditionally | Manufactures false accusations. Worse than having no system |

### What was chosen

Pixel-domain spread-spectrum embedding in the mid-frequency 8×8 DCT band, with keyed carriers, 512
carriers per payload bit, and a repetition code that tolerates a substantial share of lost carriers.

---

## 2. Derivation

```
inputs = {
  recipient_id, document_id, document_hash,
  session_id, fresh_nonce,
  watermark_version, policy_version
}

tag = HMAC-SHA256(vault_root_secret, "forge:watermark-tag:v1" || canonical_json(inputs))[0:8]
```

`tag` is 64 bits rendered as 16 hex characters.

Properties that follow directly:

- **No readable identity.** The output is an HMAC value; `REC-001` appears nowhere in it.
- **Session-specific.** Session id and a fresh nonce are inside the derivation, so the same recipient
  opening the same document twice gets two different tags.
- **Not interpretable without the root secret.** The root lives in the encrypted key vault. An attacker
  holding a leaked copy cannot compute what the mark should have been.
- **Deterministic and testable.** The same inputs always give the same tag, which is what lets the
  registry be a lookup table.

### Payload coding

```
80 bits = 64 tag bits + 16 CRC-16 bits over the tag
```

The CRC is a corruption detector, not a security control. Its job is to stop a garbage correlation
result from being presented as a recovered tag.

---

## 3. Carrier derivation

```
seed  = HMAC(root, "forge:watermark-carrier:v1" || document_id || document_hash || version_id || page)
blocks   = a seeded permutation of the page's 8×8 block grid
signs    = seeded ±1 pattern per (bit, carrier, coefficient)
polarity = +1 for a 1 bit, −1 for a 0 bit
```

**The carrier pattern is keyed to document identity, not to the session and not to the file's
contents.** That single decision is what makes extraction blind and survives edits to the leaked copy:
the investigator rebuilds carriers from the registry's document identity and correlates against the
leaked raster.

**The bit value rides on the sign of the correlation.** A `1` is a positive excursion, a `0` is a
negative one. Encoding `0` as "no excursion" would be destroyed by any processing.

---

## 4. Embedding

Per page:

1. Render at a fixed 200 DPI, grayscale, cropped to whole 8×8 blocks. Fixed geometry on both sides is
   what makes the block grid reproducible.
2. 8×2 DCT on every block (orthonormal, so it is exactly invertible).
3. Add `strength × polarity × sign` to four **mid-frequency** coefficients: (1,2), (2,1), (1,3), (3,1).
   Low frequencies are visible and crop badly; the top-right corner is discarded by JPEG and
   downscaling. This band is the compromise.
4. Inverse DCT.
5. **Range fit.** Text pages have saturated black on saturated white, so an added excursion clips.
   Measured on a two-page brief, naive clipping removed **45%** of the watermark energy. The page is
   therefore pulled very slightly toward mid-grey — by a measured factor of about 0.97 — which removes
   the clipping for a fraction of the loss.
6. Rebuild the PDF with the marked rasters.

Measured cost of the whole operation, against the original render:

| Metric | Value |
|---|---|
| PSNR | **37.0 dB** |
| SSIM | **0.967** |
| Contrast scale applied | 0.97 |
| Payload | 80 bits × 512 carriers |

A copy-to-copy comparison (two independent marks) sits near 33 dB / 0.94 SSIM, since the difference
is two marks rather than one. The claim being made is visual equivalence, not pixel identity.

---

## 5. Extraction (blind)

```
leaked file
  → rasterise at 200 DPI
  → canonicalise across candidate scale factors (1.0, 0.5, 2.0, 1.5, 0.75)
  → rebuild carriers from root + candidate document identity
  → correlate per payload bit
  → estimate the noise floor WITHIN each bit's carrier set
  → soft decide, check CRC
  → registry lookup, Hamming distance to candidate tags
  → verdict
```

The original document is **not** an input. That matters because a leaked copy's hash will never match
the original — the watermarking step changed it.

### The noise floor

Estimated as the median within-bit spread across carriers, then reduced to the standard error of the
bit mean by dividing by √n.

Measuring the spread *across* bits instead would mistake the signal for noise, because the bits
alternate between two amplitudes. That mistake produced implausible confidence figures in an earlier
version of this engine, and `tests/test_watermark.py::TestSoftDecision` now pins both cases: strong
signal must score high, pure noise must score low.

### Scale canonicalisation

A screenshot or scan at a different resolution shifts the block grid, which destroys a naive
correlation. Each candidate scale is mapped back to canonical geometry before correlating. Upscaling
beyond the embedding resolution is the weakest case and is reported honestly when it fails.

---

## 6. Verdicts

| Verdict | Condition |
|---|---|
| `FOUND` | Exact registry match, CRC intact, carrier-to-noise ≥ 3.0 |
| `WEAK MATCH` | Hamming distance ≤ 6 with signal above the weak threshold |
| `CORRUPTED` | Payload recovered and CRC valid, but no registered session matches |
| `NOT FOUND` | No usable carrier energy |

Confidence is **capped below 1.0** by design. A recovered watermark is strong evidence, never certainty,
and a display of "100%" would misrepresent what the system knows.

Thresholds come from the measured calibration, where a clean recovery sits near 7 and the worst tested
transformation near 4. A threshold of 3.0 leaves margin without ever promoting a weak match to certain.

---

## 7. Measured robustness

Run `scripts/calibrate_watermark.py` to reproduce these figures, or the **WATERMARK ENGINE** screen to
re-measure in the running deployment.

| Transformation | Recovered | Carrier-to-noise |
|---|---|---|
| Clean | yes | 10.2 |
| PDF re-save | yes | 10.2 |
| JPEG quality 70 | yes | 11.9 |
| 50% downscale | yes | 6.2 |
| 150% upscale | yes | 10.2 |
| Re-import after canonicalisation | yes | 10.2 |

**6 of 6 transformations recovered.**

### Not tested, and not claimed

- Angled photography
- Heavy cropping
- Print/scan on real hardware
- Image-model regeneration
- Collusion between recipients

These are expected to defeat the mark. The system reports `NOT FOUND` rather than guessing, and
`tests/test_watermark.py::test_heavy_crop_is_reported_as_not_found` asserts that behaviour so it cannot
silently regress.

---

## 8. Known limitations

1. **Invisible is not un-copyable.** The mark does not prevent copying, photographing or screen capture.
   It is an attribution control, not a data-loss-prevention control.
2. **Collusion.** Two recipients who difference their copies can estimate the embedding pattern.
   Collusion-resistant watermarking is a separate research problem.
3. **Rasterisation.** Embedding renders pages to images, so a watermarked PDF loses selectable text.
   This is a deliberate trade-off of pixel-domain watermarking; a controlled viewer with overlay marking
   is the production alternative.
4. **Capture limits.** Angled photography, heavy crop and print/scan are not robust.
5. **Single root secret.** All watermark derivation depends on one vault-held secret. Production should
   split this across custodians or derive per-document keys held in hardware.
6. **Repetition coding, not an optimal code.** Repetition with soft-decision combining is adequate at
   the measured signal-to-noise ratios and easy to verify. Reed–Solomon or LDPC would give stronger
   performance in the marginal cases.

---

## 9. Visual quality

PSNR and SSIM are reported on every generated copy and stored on the watermark record, so the
"visually equivalent" claim is measurable per session rather than asserted once in documentation.

```sql
SELECT psnr_db, ssim FROM watermarks ORDER BY watermark_id DESC LIMIT 10;
```

Anything below the documented floor is a signal that the embedding parameters drifted from the
calibration, and `scripts/calibrate_watermark.py` exists to re-establish them.
