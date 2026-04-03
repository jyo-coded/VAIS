"""
ml/dataset_loader.py
────────────────────
Real vulnerability dataset downloader and preprocessor.

Downloads three public datasets:
  1. Devign       — google/devign   (HuggingFace)
  2. CVEfixes     — secureIT/cvefixes (HuggingFace), Python + Java only
  3. MegaVul      — Seahorse6/megavul (HuggingFace), fallback: BigVul CSV

Output: DatasetResult with unified X (structural features), y (binary labels),
        raw_code, language, and 80/20 stratified train/test split.
"""

from __future__ import annotations

import re
import logging
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

log = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

BIGVUL_CSV_URL = (
    "https://raw.githubusercontent.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset"
    "/master/all_c_cpp_release2.0.csv"
)

SUPPORTED_LANGUAGES = {"c", "cpp", "python", "java", "go"}

# Structural feature extraction caps
MAX_TOKENS     = 512
MAX_LINES      = 200
MAX_DEPTH      = 20
MAX_CALLS      = 50
MAX_BRANCHES   = 30


# ─── Output contract ──────────────────────────────────────────────────────────

@dataclass
class DatasetResult:
    """
    Unified output of dataset_loader.

    Fields
    ------
    X           : np.ndarray  shape (N, F) float32 — structural features
    y           : np.ndarray  shape (N,)   int32   — 0=safe, 1=vulnerable
    raw_code    : list[str]  — raw source code snippets
    language    : list[str]  — per-sample language tag
    X_train     : np.ndarray  shape (N_train, F)
    X_test      : np.ndarray  shape (N_test,  F)
    y_train     : np.ndarray  shape (N_train,)
    y_test      : np.ndarray  shape (N_test,)
    raw_train   : list[str]
    raw_test    : list[str]
    lang_train  : list[str]
    lang_test   : list[str]
    sources     : list[str]   — which dataset each sample came from
    n_features  : int
    """
    X:          np.ndarray = field(default_factory=lambda: np.zeros((0, 8), dtype=np.float32))
    y:          np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int32))
    raw_code:   list       = field(default_factory=list)
    language:   list       = field(default_factory=list)
    sources:    list       = field(default_factory=list)

    X_train:    np.ndarray = field(default_factory=lambda: np.zeros((0, 8), dtype=np.float32))
    X_test:     np.ndarray = field(default_factory=lambda: np.zeros((0, 8), dtype=np.float32))
    y_train:    np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int32))
    y_test:     np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int32))
    raw_train:  list       = field(default_factory=list)
    raw_test:   list       = field(default_factory=list)
    lang_train: list       = field(default_factory=list)
    lang_test:  list       = field(default_factory=list)

    n_features: int        = 8

    def summary(self) -> dict:
        return {
            "total":       len(self.y),
            "vulnerable":  int(self.y.sum()),
            "safe":        int((self.y == 0).sum()),
            "n_train":     len(self.y_train),
            "n_test":      len(self.y_test),
            "languages":   dict(zip(*np.unique(self.language, return_counts=True)))
                           if self.language else {},
            "n_features":  self.n_features,
        }

    def __repr__(self) -> str:
        s = self.summary()
        return (f"DatasetResult(total={s['total']}, vuln={s['vulnerable']}, "
                f"safe={s['safe']}, train={s['n_train']}, test={s['n_test']})")


# ─── Structural feature extractor ────────────────────────────────────────────

FEATURE_NAMES = [
    "n_tokens",          # normalised token count
    "n_lines",           # normalised line count
    "avg_line_len",      # average characters per line (normalised)
    "n_function_calls",  # normalised function-call count
    "n_branches",        # normalised branch count (if/else/switch)
    "max_nesting_depth", # normalised nesting depth
    "has_pointer_ops",   # binary: *, &, ->, malloc/new present
    "cyclomatic_proxy",  # (branches + 1) normalised — proxy for complexity
]
N_FEATURES = len(FEATURE_NAMES)


def extract_structural_features(code: str, language: str = "c") -> np.ndarray:
    """
    Extract 8 lightweight structural features from raw source code.
    Does NOT require Tree-sitter — pure regex-based, fast and portable.
    """
    lines = code.splitlines()
    n_lines = min(len(lines), MAX_LINES)

    # Token count (whitespace split)
    tokens = code.split()
    n_tokens = min(len(tokens), MAX_TOKENS)

    # Average line length
    non_empty = [l for l in lines if l.strip()]
    avg_line_len = (sum(len(l) for l in non_empty) / len(non_empty)) if non_empty else 0
    avg_line_len = min(avg_line_len / 120.0, 1.0)   # normalise to ~120 chars max

    # Function calls: identifier followed by (
    calls = re.findall(r'\b\w+\s*\(', code)
    n_calls = min(len(calls), MAX_CALLS)

    # Branches
    branch_kws = r'\b(?:if|else|elif|switch|case|for|while|do|try|catch|except|finally)\b'
    n_branches = min(len(re.findall(branch_kws, code)), MAX_BRANCHES)

    # Max nesting depth — count indentation levels
    max_depth = 0
    for line in lines:
        stripped = line.lstrip()
        if stripped:
            indent = len(line) - len(stripped)
            spaces = indent // 4 if '\t' not in line else indent  # rough
            max_depth = max(max_depth, spaces)
    max_depth = min(max_depth, MAX_DEPTH)

    # Pointer / unsafe ops
    ptr_patterns = r'(?:\*\s*\w|\w\s*->|\bmalloc\b|\bfree\b|\bnew\b|\bdelete\b|&\w)'
    has_pointer = 1.0 if re.search(ptr_patterns, code) else 0.0

    # Cyclomatic proxy = branches + 1
    cyclomatic = min(n_branches + 1, MAX_BRANCHES + 1) / (MAX_BRANCHES + 1)

    feat = np.array([
        n_tokens   / MAX_TOKENS,
        n_lines    / MAX_LINES,
        avg_line_len,
        n_calls    / MAX_CALLS,
        n_branches / MAX_BRANCHES,
        max_depth  / MAX_DEPTH,
        has_pointer,
        cyclomatic,
    ], dtype=np.float32)

    return np.clip(feat, 0.0, 1.0)


# ─── Individual dataset loaders ───────────────────────────────────────────────

def _load_devign() -> tuple[list[str], list[int], list[str]]:
    """
    Load google/devign from HuggingFace.
    Returns (code_list, label_list, language_list).
    Labels: 1=vulnerable, 0=safe.
    """
    try:
        from datasets import load_dataset
    except ImportError:
        log.warning("HuggingFace `datasets` not installed — skipping Devign.")
        return [], [], []

    try:
        log.info("Downloading Devign (google/devign)…")
        ds = load_dataset("google/devign", split="train")
        codes, labels, langs = [], [], []
        for row in ds:
            code = row.get("func", row.get("code", ""))
            label = int(row.get("target", 0))
            if not code or not isinstance(code, str):
                continue
            codes.append(code)
            labels.append(label)
            langs.append("c")   # Devign is C/C++ functions
        log.info(f"Devign: {len(codes)} samples loaded.")
        return codes, labels, langs
    except Exception as e:
        log.warning(f"Devign load failed: {e}")
        return [], [], []


def _load_cvefixes(max_samples: int = 10_000) -> tuple[list[str], list[int], list[str]]:
    """
    Load secureIT/cvefixes from HuggingFace.
    Filters to Python and Java files only.
    Before-fix → label=1 (vulnerable), after-fix → label=0 (safe).
    """
    try:
        from datasets import load_dataset
    except ImportError:
        log.warning("HuggingFace `datasets` not installed — skipping CVEfixes.")
        return [], [], []

    target_langs = {"python", "java"}

    try:
        log.info("Downloading CVEfixes (secureIT/cvefixes)…")
        # CVEfixes has a 'commits' split with method-level code changes
        ds = load_dataset("secureIT/cvefixes", split="train", streaming=True)
        codes, labels, langs = [], [], []
        seen_hashes = set()  # dedup

        for row in ds:
            if len(codes) >= max_samples:
                break

            lang = (row.get("programming_language") or
                    row.get("language") or "").lower().strip()
            if lang not in target_langs:
                continue

            # Before-fix code (vulnerable)
            before = (row.get("before_change") or
                      row.get("old_code") or
                      row.get("func_before") or "")
            after = (row.get("after_change") or
                     row.get("new_code") or
                     row.get("func_after") or "")

            for code, lbl in [(before, 1), (after, 0)]:
                if not code or len(code.strip()) < 20:
                    continue
                h = hashlib.md5(code.encode()).hexdigest()
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)
                codes.append(code)
                labels.append(lbl)
                langs.append(lang)

        log.info(f"CVEfixes: {len(codes)} samples loaded.")
        return codes, labels, langs
    except Exception as e:
        log.warning(f"CVEfixes load failed: {e}")
        return [], [], []


def _load_megavul_or_bigvul(max_samples: int = 10_000) -> tuple[list[str], list[int], list[str]]:
    """
    Try MegaVul (Seahorse6/megavul) first.
    Fall back to BigVul CSV download from GitHub if MegaVul is unavailable.
    """
    try:
        from datasets import load_dataset
    except ImportError:
        log.warning("HuggingFace `datasets` not installed — trying BigVul CSV fallback.")
        return _load_bigvul_csv(max_samples)

    # ── Try MegaVul ──────────────────────────────────────────────────────────
    try:
        log.info("Downloading MegaVul (Seahorse6/megavul)…")
        ds = load_dataset("Seahorse6/megavul", split="train", streaming=True)
        codes, labels, langs = [], [], []
        for row in ds:
            if len(codes) >= max_samples:
                break
            code = row.get("func", row.get("code", ""))
            label = int(row.get("vul", row.get("label", 0)))
            lang = (row.get("language") or "c").lower()
            if not code:
                continue
            codes.append(code)
            labels.append(label)
            langs.append(lang)
        if codes:
            log.info(f"MegaVul: {len(codes)} samples loaded.")
            return codes, labels, langs
    except Exception as e:
        log.warning(f"MegaVul unavailable ({e}), falling back to BigVul CSV.")

    return _load_bigvul_csv(max_samples)


def _load_bigvul_csv(max_samples: int = 10_000) -> tuple[list[str], list[int], list[str]]:
    """Download BigVul CSV from GitHub and parse function-level samples."""
    import tempfile
    import urllib.request
    import csv

    cache_path = Path(tempfile.gettempdir()) / "bigvul_all_c_cpp.csv"

    if not cache_path.exists():
        try:
            log.info(f"Downloading BigVul CSV from GitHub → {cache_path}…")
            urllib.request.urlretrieve(BIGVUL_CSV_URL, str(cache_path))
        except Exception as e:
            log.warning(f"BigVul CSV download failed: {e}")
            return [], [], []

    codes, labels, langs = [], [], []
    try:
        with open(cache_path, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if len(codes) >= max_samples:
                    break
                code = row.get("func_before") or row.get("func", "")
                lbl  = int(row.get("vul", 0))
                lang = (row.get("lang") or "c").lower()
                if not code or len(code.strip()) < 20:
                    continue
                codes.append(code)
                labels.append(lbl)
                langs.append(lang)
        log.info(f"BigVul: {len(codes)} samples loaded.")
    except Exception as e:
        log.warning(f"BigVul CSV parse failed: {e}")

    return codes, labels, langs


# ─── Stratified split ─────────────────────────────────────────────────────────

def _stratified_split(
    X: np.ndarray,
    y: np.ndarray,
    raw_code: list,
    language: list,
    sources: list,
    test_size: float = 0.20,
    random_state: int = 42,
) -> DatasetResult:
    """80/20 stratified split by label and language."""
    from sklearn.model_selection import train_test_split

    # Build stratification key: label × language
    strat_keys = [f"{lbl}_{lang}" for lbl, lang in zip(y, language)]

    try:
        (X_tr, X_te, y_tr, y_te,
         rc_tr, rc_te, la_tr, la_te,
         so_tr, so_te) = train_test_split(
            X, y, raw_code, language, sources,
            test_size=test_size,
            random_state=random_state,
            stratify=strat_keys,
        )
    except ValueError:
        # Fall back to unstratified split if any stratum is too small
        (X_tr, X_te, y_tr, y_te,
         rc_tr, rc_te, la_tr, la_te,
         so_tr, so_te) = train_test_split(
            X, y, raw_code, language, sources,
            test_size=test_size,
            random_state=random_state,
        )

    return DatasetResult(
        X=X, y=y, raw_code=raw_code, language=language, sources=sources,
        X_train=X_tr,  X_test=X_te,
        y_train=y_tr,  y_test=y_te,
        raw_train=list(rc_tr), raw_test=list(rc_te),
        lang_train=list(la_tr), lang_test=list(la_te),
        n_features=N_FEATURES,
    )


# ─── Public API ───────────────────────────────────────────────────────────────

def load_all_datasets(
    max_per_dataset: int = 10_000,
    test_size: float = 0.20,
    random_state: int = 42,
    use_devign: bool = True,
    use_cvefixes: bool = True,
    use_megavul: bool = True,
    cache_dir: Optional[str] = None,
) -> DatasetResult:
    """
    Download, preprocess, and merge all three vulnerability datasets.

    Parameters
    ----------
    max_per_dataset : int
        Maximum samples to load from each dataset.
    test_size : float
        Fraction of data reserved for testing (default 0.20).
    random_state : int
        Reproducibility seed.
    use_devign / use_cvefixes / use_megavul : bool
        Toggle individual datasets.
    cache_dir : str | None
        HuggingFace cache directory (uses HF default if None).

    Returns
    -------
    DatasetResult — unified dataset ready for training.
    """
    if cache_dir:
        import os
        os.environ["HF_HOME"] = cache_dir

    all_codes:  list[str] = []
    all_labels: list[int] = []
    all_langs:  list[str] = []
    all_sources: list[str] = []

    # ── Load each dataset ─────────────────────────────────────────────────────
    if use_devign:
        c, l, la = _load_devign()
        all_codes  += c
        all_labels += l
        all_langs  += la
        all_sources += ["devign"] * len(c)

    if use_cvefixes:
        c, l, la = _load_cvefixes(max_per_dataset)
        all_codes  += c
        all_labels += l
        all_langs  += la
        all_sources += ["cvefixes"] * len(c)

    if use_megavul:
        c, l, la = _load_megavul_or_bigvul(max_per_dataset)
        all_codes  += c
        all_labels += l
        all_langs  += la
        all_sources += ["megavul_or_bigvul"] * len(c)

    if not all_codes:
        log.warning("No data loaded from any dataset. Returning empty DatasetResult.")
        return DatasetResult()

    # ── Dedup by code hash ────────────────────────────────────────────────────
    seen: set[str] = set()
    deduped_codes, deduped_labels, deduped_langs, deduped_sources = [], [], [], []
    for code, lbl, lang, src in zip(all_codes, all_labels, all_langs, all_sources):
        h = hashlib.md5(code.encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            deduped_codes.append(code)
            deduped_labels.append(lbl)
            deduped_langs.append(lang)
            deduped_sources.append(src)

    log.info(f"Total unique samples after dedup: {len(deduped_codes)}")

    # ── Extract structural features ───────────────────────────────────────────
    log.info("Extracting structural features…")
    X_rows = [
        extract_structural_features(code, lang)
        for code, lang in zip(deduped_codes, deduped_langs)
    ]
    X = np.vstack(X_rows).astype(np.float32)
    y = np.array(deduped_labels, dtype=np.int32)

    # ── Stratified 80/20 split ────────────────────────────────────────────────
    result = _stratified_split(
        X, y, deduped_codes, deduped_langs, deduped_sources,
        test_size=test_size, random_state=random_state,
    )

    log.info(f"Dataset ready: {result}")
    return result


# ─── CLI convenience ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    result = load_all_datasets(max_per_dataset=2000)
    print(result)
    print(result.summary())
