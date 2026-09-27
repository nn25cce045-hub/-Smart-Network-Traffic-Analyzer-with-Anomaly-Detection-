"""Small rolling baseline used by traffic-spike detection."""

from __future__ import annotations

from collections import deque
from statistics import fmean


class RollingBaseline:
    """Maintain a fixed-size moving average of numeric samples."""

    def __init__(self, window_size: int, minimum_samples: int) -> None:
        if window_size < 1:
            raise ValueError("window_size must be positive")
        if not 1 <= minimum_samples <= window_size:
            raise ValueError("minimum_samples must be between 1 and window_size")
        self.window_size = window_size
        self.minimum_samples = minimum_samples
        self._samples: deque[float] = deque(maxlen=window_size)

    def add(self, value: float) -> None:
        self._samples.append(max(0.0, float(value)))

    @property
    def average(self) -> float:
        return fmean(self._samples) if self._samples else 0.0

    @property
    def sample_count(self) -> int:
        return len(self._samples)

    @property
    def ready(self) -> bool:
        return len(self._samples) >= self.minimum_samples

    def reset(self) -> None:
        self._samples.clear()

