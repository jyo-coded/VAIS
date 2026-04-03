"""
ml/codebert_model.py
────────────────────
Fine-tuned CodeBERT binary classifier for vulnerability detection.

Model   : microsoft/codebert-base
Task    : Binary sequence classification  (0=safe, 1=vulnerable)
Training: HuggingFace Trainer
Hardware: Optimised for RTX 3050 4 GB VRAM
  - batch_size=8, gradient_accumulation=4 (effective 32)
  - fp16 mixed precision
  - Truncate/pad to 512 tokens

Saved to : models/codebert_vuln/

Public API
----------
  train_codebert(dataset_result, output_dir)  -> CodeBERTPredictor
  CodeBERTPredictor.predict(code)             -> float  (0..1)
  CodeBERTPredictor.load(checkpoint_dir)      -> CodeBERTPredictor
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional, Union

import numpy as np

log = logging.getLogger(__name__)

# ─── HuggingFace model ID ────────────────────────────────────────────────────
MODEL_ID        = "microsoft/codebert-base"
MAX_LENGTH      = 512
DEFAULT_OUT_DIR = "models/codebert_vuln"

# ─── Training hyperparameters ─────────────────────────────────────────────────
TRAIN_ARGS = dict(
    num_train_epochs          = 3,
    per_device_train_batch_size = 8,
    per_device_eval_batch_size  = 16,
    gradient_accumulation_steps = 4,       # effective batch = 32
    learning_rate             = 2e-5,
    weight_decay              = 0.01,
    warmup_steps              = 100,
    evaluation_strategy       = "epoch",
    save_strategy             = "epoch",
    load_best_model_at_end    = True,
    metric_for_best_model     = "f1",
    greater_is_better         = True,
    fp16                      = True,      # RTX 3050 supports FP16
    dataloader_num_workers    = 0,         # Windows compatibility
    report_to                 = "none",
    logging_steps             = 50,
    seed                      = 42,
)


# ─── HuggingFace Dataset wrapper ─────────────────────────────────────────────

def _build_hf_dataset(codes: list[str], labels: list[int], tokenizer):
    """Tokenize code snippets and wrap as a HuggingFace Dataset."""
    try:
        from datasets import Dataset as HFDataset
    except ImportError:
        raise RuntimeError("pip install datasets transformers torch")

    raw = {"code": codes, "label": labels}
    ds  = HFDataset.from_dict(raw)

    def tokenize(batch):
        return tokenizer(
            batch["code"],
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH,
        )

    ds = ds.map(tokenize, batched=True, remove_columns=["code"])
    ds = ds.rename_column("label", "labels")
    ds.set_format(type="torch", columns=["input_ids", "attention_mask", "labels"])
    return ds


# ─── Metrics ─────────────────────────────────────────────────────────────────

def _compute_metrics(eval_pred):
    """Called by HuggingFace Trainer each evaluation epoch."""
    from sklearn.metrics import f1_score, accuracy_score, roc_auc_score

    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    proba = _softmax(logits)[:, 1]

    acc = float(accuracy_score(labels, preds))
    f1  = float(f1_score(labels, preds, zero_division=0))
    try:
        auc = float(roc_auc_score(labels, proba))
    except ValueError:
        auc = 0.5

    return {"accuracy": acc, "f1": f1, "auc_roc": auc}


def _softmax(logits: np.ndarray) -> np.ndarray:
    e = np.exp(logits - logits.max(axis=1, keepdims=True))
    return e / e.sum(axis=1, keepdims=True)


# ─── Trainer / fine-tuner ─────────────────────────────────────────────────────

def train_codebert(
    dataset_result,
    output_dir: str = DEFAULT_OUT_DIR,
    resume_from: Optional[str] = None,
) -> "CodeBERTPredictor":
    """
    Fine-tune CodeBERT on the provided DatasetResult.

    Parameters
    ----------
    dataset_result : DatasetResult
        From ml.dataset_loader.load_all_datasets()
    output_dir : str
        Directory to save the fine-tuned model and tokenizer.
    resume_from : str | None
        Path to a previous checkpoint to resume from.

    Returns
    -------
    CodeBERTPredictor — ready for inference.
    """
    try:
        from transformers import (
            AutoTokenizer, AutoModelForSequenceClassification,
            TrainingArguments, Trainer,
            EarlyStoppingCallback,
        )
    except ImportError:
        raise RuntimeError(
            "transformers not installed. Run: pip install transformers torch"
        )

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    log.info(f"Loading tokenizer: {MODEL_ID}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)

    log.info(f"Loading model:     {MODEL_ID}")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_ID,
        num_labels=2,
        ignore_mismatched_sizes=True,
    )

    # ── Build HF datasets ─────────────────────────────────────────────────────
    log.info("Tokenising training data…")
    train_ds = _build_hf_dataset(
        dataset_result.raw_train, dataset_result.y_train.tolist(), tokenizer
    )
    log.info("Tokenising test/eval data…")
    eval_ds  = _build_hf_dataset(
        dataset_result.raw_test, dataset_result.y_test.tolist(), tokenizer
    )

    # ── Compute class weights for imbalanced data ─────────────────────────────
    y_tr = np.array(dataset_result.y_train)
    n_pos = int(y_tr.sum())
    n_neg = int((y_tr == 0).sum())
    pos_weight = n_neg / max(n_pos, 1)
    log.info(f"Class balance — pos:{n_pos}  neg:{n_neg}  pos_weight:{pos_weight:.2f}")

    # ── Training arguments ────────────────────────────────────────────────────
    training_args = TrainingArguments(
        output_dir=str(out_path),
        **TRAIN_ARGS,
    )

    # ── Weighted loss trainer ─────────────────────────────────────────────────
    import torch

    class WeightedLossTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels   = inputs.pop("labels")
            outputs  = model(**inputs)
            logits   = outputs.logits
            weight   = torch.tensor([1.0, pos_weight], device=logits.device, dtype=logits.dtype)
            loss_fn  = torch.nn.CrossEntropyLoss(weight=weight)
            loss     = loss_fn(logits, labels)
            return (loss, outputs) if return_outputs else loss

    trainer = WeightedLossTrainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        compute_metrics=_compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    log.info("Starting fine-tuning…")
    trainer.train(resume_from_checkpoint=resume_from)

    # ── Save model + tokenizer ────────────────────────────────────────────────
    log.info(f"Saving model to {out_path}/")
    trainer.save_model(str(out_path))
    tokenizer.save_pretrained(str(out_path))

    log.info("CodeBERT fine-tuning complete.")
    return CodeBERTPredictor(model=model, tokenizer=tokenizer)


# ─── Inference wrapper ────────────────────────────────────────────────────────

class CodeBERTPredictor:
    """
    Thin wrapper around a fine-tuned CodeBERT for single-code inference.

    Usage
    -----
    predictor = CodeBERTPredictor.load("models/codebert_vuln/")
    prob = predictor.predict(source_code_string)   # float in [0, 1]
    """

    def __init__(self, model=None, tokenizer=None, device: Optional[str] = None):
        self._model     = model
        self._tokenizer = tokenizer
        self._device    = device or self._detect_device()
        if self._model is not None:
            self._model.to(self._device)
            self._model.eval()

    @staticmethod
    def _detect_device() -> str:
        try:
            import torch
            return "cuda" if torch.cuda.is_available() else "cpu"
        except ImportError:
            return "cpu"

    @classmethod
    def load(cls, checkpoint_dir: str = DEFAULT_OUT_DIR) -> "CodeBERTPredictor":
        """
        Load a fine-tuned model from a saved directory.

        Parameters
        ----------
        checkpoint_dir : str
            Directory containing config.json, pytorch_model.bin, tokenizer files.

        Returns
        -------
        CodeBERTPredictor ready for inference.
        """
        try:
            from transformers import (
                AutoTokenizer,
                AutoModelForSequenceClassification,
            )
        except ImportError:
            raise RuntimeError("pip install transformers torch")

        path = Path(checkpoint_dir)
        if not path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {path}")

        log.info(f"Loading CodeBERT from {path}")
        tokenizer = AutoTokenizer.from_pretrained(str(path))
        model     = AutoModelForSequenceClassification.from_pretrained(str(path))
        return cls(model=model, tokenizer=tokenizer)

    def predict(self, code: str) -> float:
        """
        Predict vulnerability probability for a single code snippet.

        Parameters
        ----------
        code : str
            Raw source code (any language).

        Returns
        -------
        float in [0.0, 1.0] — probability that the code is vulnerable.
        """
        if self._model is None or self._tokenizer is None:
            raise RuntimeError("Model not loaded. Call CodeBERTPredictor.load() first.")

        import torch

        inputs = self._tokenizer(
            code,
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH,
            return_tensors="pt",
        ).to(self._device)

        with torch.no_grad():
            logits = self._model(**inputs).logits

        proba = torch.softmax(logits, dim=-1)
        return float(proba[0, 1].cpu().item())

    def predict_batch(self, codes: list[str], batch_size: int = 16) -> np.ndarray:
        """
        Predict vulnerability probabilities for a list of code snippets.

        Returns
        -------
        np.ndarray of shape (N,) with probabilities in [0, 1].
        """
        probs = []
        for i in range(0, len(codes), batch_size):
            batch = codes[i : i + batch_size]
            probs.extend(self.predict(c) for c in batch)
        return np.array(probs, dtype=np.float32)

    @property
    def is_loaded(self) -> bool:
        return self._model is not None and self._tokenizer is not None


# ─── CLI training entrypoint ──────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    from ml.dataset_loader import load_all_datasets

    dataset = load_all_datasets(max_per_dataset=5000)
    print(dataset)

    predictor = train_codebert(dataset, output_dir=DEFAULT_OUT_DIR)
    print("Sample prediction:", predictor.predict("int x = malloc(10); free(x); x[0] = 1;"))
