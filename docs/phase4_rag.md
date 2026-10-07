# Phase 4: Retrieval augmented generation

## Implementation

- Curated project-authored analyst guidance is stored under `data/knowledge_base/standards/`.
- `app/rag/chunking.py` splits text into bounded overlapping passages.
- `app/rag/embeddings.py` builds offline sparse vectors with curated dependency-security concept groups; TF-IDF remains available as a fallback.
- `app/rag/vector_store.py` ranks passages by cosine similarity in an in-memory vector store.
- `app/rag/retriever.py` returns passages with source paths and similarity values.

This is a lightweight concept-expanded vector baseline. Synonyms in the curated vocabulary share vector dimensions, and ranking uses cosine similarity. It does not use pretrained transformer embeddings, a hosted embedding API, or a persistent database; semantic generalization is limited to the authored concept map. Keeping it local avoids sending the corpus to a service.

## Without RAG vs with RAG

The Streamlit sidebar can disable RAG. With RAG enabled, the evidence payload includes matched guidance and source paths; with RAG disabled, it reports `without_rag` and has no retrieved guidance. Vulnerability lookup remains a separate structured tool and is never replaced by RAG.

## Limits

The included guidance corpus is small and project-authored. Retrieval relevance on the offline cases does not establish broad semantic quality or authoritative security coverage. Documents must be curated and versioned before production use.
