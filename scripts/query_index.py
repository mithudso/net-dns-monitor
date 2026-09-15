#!/usr/bin/env python3
import sys
import chromadb
from chromadb.utils import embedding_functions
import os

if len(sys.argv) < 2:
    print("Usage: python3 query_index.py 'your question here'")
    sys.exit(1)

query = " ".join(sys.argv[1:])
client = chromadb.PersistentClient(path=os.path.join(os.path.dirname(__file__), "..", ".chroma_db"))

ollama_ef = embedding_functions.OllamaEmbeddingFunction(
    url="http://localhost:11434/api/embeddings",
    model_name="nomic-embed-text"
)

collection = client.get_collection(name="codebase_index", embedding_function=ollama_ef)

results = collection.query(
    query_texts=[query],
    n_results=3
)

print(f"\n🔍 Results for: '{query}'\n")
for i in range(len(results['documents'][0])):
    print(f"📄 Source: {results['metadatas'][0][i]['source']}")
    print(f"{results['documents'][0][i]}\n{'-'*40}")
