"""Local language-model backends (zero cost): MLX on Apple silicon, with a disk cache.

Every completion is cached by (model, prompt) so experiments are resumable and exactly
reproducible; decoding is greedy (temperature 0).
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

MODELS = {
    "qwen2.5-7b": "mlx-community/Qwen2.5-7B-Instruct-4bit",
    "qwen2.5-3b": "mlx-community/Qwen2.5-3B-Instruct-4bit",
}


class MLXBackend:
    def __init__(self, name: str = "qwen2.5-7b", cache_dir: str | Path = "results/llm_cache", max_tokens: int = 1200):
        self.name = name
        self.repo = MODELS.get(name, name)
        self.cache = Path(cache_dir) / name
        self.cache.mkdir(parents=True, exist_ok=True)
        self.max_tokens = max_tokens
        self._model = None

    def _load(self):
        if self._model is None:
            from mlx_lm import load
            self._model, self._tok = load(self.repo)

    def complete(self, system: str, user: str, max_tokens: int | None = None) -> dict:
        key = hashlib.sha256(json.dumps([self.repo, system, user, max_tokens or self.max_tokens]).encode()).hexdigest()[:24]
        path = self.cache / f"{key}.json"
        if path.exists():
            return {**json.loads(path.read_text()), "cached": True}
        self._load()
        from mlx_lm import generate
        prompt = self._tok.apply_chat_template([{"role": "system", "content": system}, {"role": "user", "content": user}],
                                               add_generation_prompt=True, tokenize=False)
        n_in = len(self._tok.encode(prompt))
        t0 = time.time()
        text = generate(self._model, self._tok, prompt=prompt, max_tokens=max_tokens or self.max_tokens, verbose=False)
        out = {"text": text, "seconds": time.time() - t0, "prompt_tokens": n_in,
               "completion_tokens": len(self._tok.encode(text)), "model": self.repo}
        path.write_text(json.dumps(out))
        return {**out, "cached": False}


def parse_json(text: str):
    """Extract the first JSON object from a model reply (tolerates code fences and trailing prose)."""
    text = re.sub(r"```(?:json)?", "", text)
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None
