"""Load curated Markdown/text and retrieve relevant passages."""
from pathlib import Path
from app.config import ROOT, RAG_TOP_K
from app.rag.vector_store import LocalVectorStore
from app.rag.chunking import chunk_text
from app.rag.embeddings import semantic_features, tokenize


def load_documents(directory: Path | None = None) -> list[dict]:
    root = directory or ROOT / "data" / "knowledge_base"
    docs = []
    if not root.exists():
        return docs
    for path in sorted([*root.rglob("*.md"), *root.rglob("*.txt")]):
        text = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
        if text.strip():
            relative = str(path.relative_to(ROOT))
            for index, passage in enumerate(chunk_text(text[:50000])):
                docs.append({"id": f"{path.relative_to(root).as_posix()}#chunk-{index + 1}", "source": relative, "chunk": index + 1, "text": passage})
    return docs


def retrieve(query: str, top_k: int = RAG_TOP_K, directory: Path | None = None) -> list[dict]:
    query_features = set(semantic_features(query))
    if not query_features:
        return []
    documents = load_documents(directory)
    if not documents:
        return []
    hits = LocalVectorStore(documents).search(query, top_k=top_k)
    # Semantic feature overlap prevents generic single-concept matches.
    # A query that maps entirely to one curated concept still needs only that
    # one feature; otherwise require two distinct shared dimensions.
    accepted = []
    for hit in hits:
        shared = query_features.intersection(semantic_features(hit["text"]))
        minimum_shared = 1 if len(query_features) == 1 else 2
        if len(shared) >= minimum_shared:
            accepted.append(hit)
    return accepted



