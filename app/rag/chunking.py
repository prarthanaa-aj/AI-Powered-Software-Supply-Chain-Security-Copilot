"""Split text into bounded overlapping passages while keeping word boundaries."""


def chunk_text(text: str, max_chars: int = 1200, overlap: int = 160) -> list[str]:
    if max_chars < 100 or overlap < 0 or overlap >= max_chars:
        raise ValueError("Require max_chars >= 100 and 0 <= overlap < max_chars")
    remaining = " ".join(text.split())
    chunks = []
    while remaining:
        if len(remaining) <= max_chars:
            chunks.append(remaining)
            break
        boundary = remaining.rfind(" ", 0, max_chars + 1)
        if boundary < max_chars // 2:
            boundary = max_chars
        chunks.append(remaining[:boundary].strip())
        next_start = max(0, boundary - overlap)
        next_space = remaining.find(" ", next_start)
        remaining = remaining[next_space + 1:] if next_space >= 0 else remaining[boundary:]
    return [chunk for chunk in chunks if chunk]
