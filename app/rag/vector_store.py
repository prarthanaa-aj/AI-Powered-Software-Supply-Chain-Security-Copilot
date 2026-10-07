"""In-memory cosine-similarity vector store with local semantic vectors."""
from app.rag.embeddings import fit_semantic, fit_tfidf, transform, transform_semantic


class LocalVectorStore:
    """A tiny corpus vector index; semantic vectors are preferred by default."""
    def __init__(self, documents: list[dict], backend: str = "semantic"):
        if backend not in {"semantic", "tfidf"}:
            raise ValueError("backend must be 'semantic' or 'tfidf'")
        self.documents = documents
        self.backend = backend
        if backend == "semantic":
            self.vectors, self.idf = fit_semantic([doc["text"] for doc in documents])
            self._transform = transform_semantic
        else:
            self.vectors, self.idf = fit_tfidf([doc["text"] for doc in documents])
            self._transform = transform

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        if top_k <= 0:
            return []
        query_vector = self._transform(query, self.idf)
        scored = []
        for doc, vector in zip(self.documents, self.vectors):
            score = sum(value * vector.get(term, 0.0) for term, value in query_vector.items())
            if score > 0:
                scored.append({**doc, "similarity": round(score, 4), "retrieval_backend": self.backend})
        return sorted(scored, key=lambda item: item["similarity"], reverse=True)[:top_k]
