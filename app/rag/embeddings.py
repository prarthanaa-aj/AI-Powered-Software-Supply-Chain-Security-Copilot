"""Dependency-free local semantic embeddings plus a TF-IDF fallback.

The default vectors use curated domain synonym classes with IDF weighting.
They run offline and are transparent, but are not pretrained neural embeddings.
"""
import math
import re
from collections import Counter

_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{1,}", re.I)
_STOP_WORDS = set("about after again all also an and any are as at be because been before being between both but by can could did do does each for from get got had has have he her here hers him his how i if in into is it its just me more most my no not of on or our out over she should so some such than that the their them then there these they this those through to too under up us very was we were what when where which who why will with would you your".split())
_CONCEPTS = {
    "dependency": "dependency dependencies package packages library libraries component direct transitive indirect".split(),
    "vulnerability": "vulnerability vulnerabilities vulnerable security flaw exploit".split(),
    "advisory": "advisory advisories finding findings bulletin cve osv".split(),
    "version": "version versions release releases installed upgrade patched".split(),
    "range": "range ranges affected introduced fixed".split(),
    "path": "path paths route routes graph".split(),
    "evidence": "evidence source sources record records proof observed".split(),
    "coverage": "coverage lookup results result missing absence unknown".split(),
    "safety": "safe safety secure harmless clean".split(),
    "exploitability": "exploitability exploitation reachable reachability runtime used".split(),
    "compatibility": "compatibility compatible breaking change changes".split(),
    "testing": "test tests testing validation".split(),
    "credentials": "credential credentials secret secrets token key password".split(),
    "code": "code repository repo files".split(),
    "score": "score scoring severity rating cvss risk".split(),
    "human_review": "human analyst review reviewer decision remediation".split(),
}
_TERM_CONCEPT = {term: concept for concept, terms in _CONCEPTS.items() for term in terms}


def tokenize(text: str) -> list[str]:
    tokens = [token.lower().strip("._-") for token in _TOKEN.findall(text)]
    return [token for token in tokens if len(token) > 1 and token not in _STOP_WORDS]


def _fit(counts: list[Counter]) -> tuple[list[dict[str, float]], dict[str, float]]:
    vocabulary = set().union(*(c.keys() for c in counts)) if counts else set()
    idf = {term: math.log(1 + (len(counts) + 1) / (sum(term in c for c in counts) + 1)) for term in vocabulary}
    vectors = []
    for counter in counts:
        vector = {term: (1 + math.log(count)) * idf[term] for term, count in counter.items()}
        norm = math.sqrt(sum(value * value for value in vector.values())) or 1.0
        vectors.append({term: value / norm for term, value in vector.items()})
    return vectors, idf


def _transform(counter: Counter, idf: dict[str, float]) -> dict[str, float]:
    vector = {term: (1 + math.log(count)) * idf[term] for term, count in counter.items() if term in idf}
    norm = math.sqrt(sum(value * value for value in vector.values())) or 1.0
    return {term: value / norm for term, value in vector.items()}


def fit_tfidf(documents: list[str]) -> tuple[list[dict[str, float]], dict[str, float]]:
    return _fit([Counter(tokenize(doc)) for doc in documents])


def transform(text: str, idf: dict[str, float]) -> dict[str, float]:
    return _transform(Counter(tokenize(text)), idf)


def semantic_features(text: str) -> Counter:
    """Map domain synonyms to shared sparse vector dimensions."""
    features = Counter()
    for token in tokenize(text):
        stem = token
        for suffix in ("ing", "ed", "es", "s"):
            if len(stem) > len(suffix) + 3 and stem.endswith(suffix):
                stem = stem[:-len(suffix)]
                break
        features["concept:" + _TERM_CONCEPT.get(token, _TERM_CONCEPT.get(stem, stem))] += 1
    return features


def fit_semantic(documents: list[str]) -> tuple[list[dict[str, float]], dict[str, float]]:
    return _fit([semantic_features(doc) for doc in documents])


def transform_semantic(text: str, idf: dict[str, float]) -> dict[str, float]:
    return _transform(semantic_features(text), idf)


