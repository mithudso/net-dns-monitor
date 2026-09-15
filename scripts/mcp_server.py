#!/usr/bin/env python3
import sys
import os
import chromadb
from chromadb.utils import embedding_functions

# FastMCP is packaged separately from the low-level MCP SDK in current releases.
from fastmcp import FastMCP

mcp = FastMCP("Local Semantic Search")

@mcp.tool()
def search_codebase(query: str, n_results: int = 3) -> str:
    """
    Search the local codebase semantically. Use this to find code snippets,
    architecture docs, or logic without reading entire files.
    """
    client = chromadb.PersistentClient(path=os.path.join(os.path.dirname(__file__), "..", ".chroma_db"))
    
    ollama_ef = embedding_functions.OllamaEmbeddingFunction(
        url="http://localhost:11434/api/embeddings",
        model_name="nomic-embed-text"
    )
    
    try:
        collection = client.get_collection(name="codebase_index", embedding_function=ollama_ef)
    except Exception as e:
        return f"Index not found. Has it been built? Error: {e}"

    results = collection.query(
        query_texts=[query],
        n_results=n_results
    )

    if not results['documents'] or not results['documents'][0]:
        return "No relevant code found."

    output = []
    for i in range(len(results['documents'][0])):
        source = results['metadatas'][0][i]['source']
        content = results['documents'][0][i]
        output.append(f"--- SOURCE: {source} ---\n{content}\n")
    
    return "\n".join(output)

if __name__ == "__main__":
    # Start the MCP server over stdio
    mcp.run()
