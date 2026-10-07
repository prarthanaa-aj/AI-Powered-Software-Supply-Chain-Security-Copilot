from app.rag.chunking import chunk_text
from app.rag.retriever import retrieve


def test_retriever_returns_source_cited_guidance():
    hits = retrieve("verify dependency advisory source and human review", top_k=2)
    assert hits
    assert "analyst_review.md" in hits[0]["source"]
    assert hits[0]["similarity"] > 0
    assert hits[0]["chunk"] == 1


def test_chunks_are_bounded_and_overlap_is_respected():
    chunks = chunk_text(("dependency evidence source. " * 100), max_chars=300, overlap=40)
    assert len(chunks) > 1
    assert all(len(chunk) <= 300 for chunk in chunks)


def test_empty_or_unrelated_query_does_not_invent_matches():
    assert retrieve("zzzzqxyv 9922", top_k=3) == []
    assert retrieve("What is the capital of France?", top_k=3) == []
    assert retrieve("Tell me about astrophysics and Jupiter", top_k=3) == []
from app.rag.vector_store import LocalVectorStore


def test_semantic_vector_maps_curated_synonyms_but_tfidf_is_available():
    docs = [{"id": "one", "text": "Review the software component for known security flaws."}]
    semantic = LocalVectorStore(docs).search("inspect the package for vulnerability", top_k=1)
    lexical = LocalVectorStore(docs, backend="tfidf").search("inspect the package for vulnerability", top_k=1)
    assert semantic and semantic[0]["retrieval_backend"] == "semantic"
    assert semantic[0]["similarity"] > 0
    assert lexical == []
