"""Règles pures de sécurité de l'interface : verrouillage, délai après échec, durées. Sans Qt, donc testables."""

from __future__ import annotations

IDLE_LOCK_SECONDS = 300  # verrouillage après 5 min sans activité
WAKE_GAP_SECONDS = 30  # un écart de plus de 30 s entre deux battements = la machine a dormi
CLIPBOARD_CLEAR_MS = 15_000  # le presse-papiers est vidé 15 s après une copie
UNLOCK_FREE_ATTEMPTS = 3  # trois échecs sans délai, puis un délai qui double à chaque échec
UNLOCK_MAX_DELAY_SECONDS = 30


def should_lock(
    last_activity: float,
    last_tick: float,
    now: float,
    idle_limit: float = IDLE_LOCK_SECONDS,
    gap_limit: float = WAKE_GAP_SECONDS,
) -> bool:
    """Vrai si le coffre doit se verrouiller maintenant. Temps en secondes (horloge murale)."""
    if now - last_tick > gap_limit:
        return True
    return now - last_activity >= idle_limit


def unlock_delay_seconds(failures: int) -> int:
    """Délai imposé avant la prochaine tentative de mot de passe, après `failures` échecs."""
    if failures < UNLOCK_FREE_ATTEMPTS:
        return 0
    return min(2 ** (failures - UNLOCK_FREE_ATTEMPTS), UNLOCK_MAX_DELAY_SECONDS)
