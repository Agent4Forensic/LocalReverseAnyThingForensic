"""DE <-> EN translation pipeline (placeholder protection, glossary, cache)."""
from sw_analyst.translate.glossary import GLOSSARY_EN_DE, GLOSSARY_VERSION, glossary_prompt_block
from sw_analyst.translate.langdetect import detect_lang
from sw_analyst.translate.pipeline import (
    TRANSLATION_PROMPT_VERSION,
    InMemoryCache,
    Translation,
    TranslationCache,
    Translator,
)
from sw_analyst.translate.protect import protect, restore

__all__ = [
    "GLOSSARY_EN_DE", "GLOSSARY_VERSION", "glossary_prompt_block", "detect_lang",
    "TRANSLATION_PROMPT_VERSION", "InMemoryCache", "Translation", "TranslationCache", "Translator",
    "protect", "restore",
]
