from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class SoftDecision:
    """Per-bit recovery result.

    The noise floor is estimated *within* each payload bit's carrier set, not
    across bits. Bits alternate between two amplitudes, so measuring the spread
    across bits mistakes the signal itself for noise and destroys any usable
    confidence figure.
    """

    values: np.ndarray
    decided: np.ndarray
    mean_abs_score: float
    noise_sigma: float
    noise_sigma_mean: float
    agreed_fraction: float

    @property
    def carrier_to_noise(self) -> float:
        """Mean recovered amplitude divided by the standard error of that mean.

        A correct recovery lands orders of magnitude above 1; a wrong carrier
        pattern or a badly rescaled capture sits near 1.
        """
        return float(self.mean_abs_score / max(self.noise_sigma_mean, 1e-12))

    def z_scores(self) -> np.ndarray:
        return np.abs(self.values) / max(self.noise_sigma_mean, 1e-12)


def robust_sigma(samples: np.ndarray) -> float:
    """Median absolute deviation, scaled to a normal distribution. Immune to the
    few blocks that carry a strong signal, unlike a plain standard deviation."""
    if samples.size == 0:
        return 1e-9
    median = np.median(samples)
    return float(1.4826 * np.median(np.abs(samples - median))) or 1e-9


def within_row_sigma(scores: np.ndarray) -> float:
    """Typical spread of the individual carrier observations inside a bit."""
    if scores.ndim != 2 or scores.shape[1] < 2:
        return 1e-9
    per_row = scores.std(axis=1)
    return float(np.median(per_row)) or 1e-9


def combine(carrier_scores: np.ndarray) -> SoftDecision:
    """carrier_scores has shape (payload_bits, carriers_per_bit); each row is
    one payload bit observed across many independent carriers."""
    if carrier_scores.ndim == 1:
        carrier_scores = carrier_scores.reshape(1, -1)
    values = carrier_scores.mean(axis=1)
    sigma = within_row_sigma(carrier_scores)
    standard_error = sigma / max(1.0, carrier_scores.shape[1] ** 0.5)
    decided = (values > 0).astype(np.int8)
    z = np.abs(values) / max(standard_error, 1e-12)
    return SoftDecision(
        values=values,
        decided=decided,
        mean_abs_score=float(np.mean(np.abs(values))),
        noise_sigma=sigma,
        noise_sigma_mean=standard_error,
        agreed_fraction=float(np.mean(z >= 3.0)),
    )


def estimate_bit_errors(decision: SoftDecision) -> int:
    """Expected number of wrong bits under a Gaussian noise model, used to report
    confidence honestly instead of assuming every recovery is perfect."""
    probabilities = _normal_sf(decision.z_scores())
    return int(round(float(np.sum(probabilities))))


def _normal_sf(z: np.ndarray) -> np.ndarray:
    from math import erfc

    return np.vectorize(lambda value: 0.5 * erfc(value / (2.0**0.5)))(z)
