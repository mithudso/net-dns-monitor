#!/usr/bin/env python3
import os
import sys

import chromadb
from chromadb.utils import embedding_functions


def index_file(filepath):
    if not os.path.exists(filepath) or not filepath.endswith(
        (".md", ".py", ".txt", ".sh", ".json")
    ):
        print(f"Skipping non-indexable file: {filepath}")
        return

    print(f"Indexing: {filepath}")

    with open(filepath, encoding="utf-8") as f:
        text = f.read()

    # Simple naive chunking
    chunk_size = 1000
    overlap = 200
    chunks = []
    start = 0
    while start < len(text):
        chunks.append(text[start : start + chunk_size])
        start += chunk_size - overlap

    if not chunks:
        return

    client = chromadb.PersistentClient(path="./.chroma_db")
    ollama_ef = embedding_functions.OllamaEmbeddingFunction(
        url="http://localhost:11434/api/embeddings", model_name="nomic-embed-text"
    )

    collection = client.get_or_create_collection(
        name="codebase_index", embedding_function=ollama_ef
    )

    ids = [f"{filepath}_chunk_{i}" for i in range(len(chunks))]
    metadatas = [{"source": filepath} for _ in chunks]

    # Upsert overwrites existing chunks with the same ID, effectively updating them
    collection.upsert(documents=chunks, metadatas=metadatas, ids=ids)
    print(f"Successfully indexed {len(chunks)} chunks for {filepath}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 semantic_indexer.py <filepath>")
        sys.exit(1)

    index_file(sys.argv[1])
