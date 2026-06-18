import chromadb
from pathlib import Path
from config import CHROMA_DB_PATH, PLAYBOOKS_PATH


class PlaybookLoader:
    """
    Loads security playbooks into ChromaDB vector database.
    ChromaDB converts text into mathematical vectors (embeddings)
    so we can search by MEANING, not just keywords.
    """

    def __init__(self):
        self.client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
        self.collection = self.client.get_or_create_collection(
            name="soc_playbooks",
            metadata={"description": "SOC incident response playbooks"}
        )

    def load_all_playbooks(self):
        """Load all .txt playbooks from the playbooks directory."""
        path = Path(PLAYBOOKS_PATH)
        loaded = 0

        for txt_file in path.glob("*.txt"):
            with open(txt_file, "r") as f:
                content = f.read()

            playbook_name = txt_file.stem  # filename without .txt

            # Add to ChromaDB
            self.collection.upsert(
                documents=[content],
                ids=[playbook_name],
                metadatas=[{"playbook_name": playbook_name, "source": str(txt_file)}]
            )
            loaded += 1
            print(f"[RAG] Loaded playbook: {playbook_name}")

        print(f"[RAG] Total playbooks loaded: {loaded}")

    def get_collection(self):
        return self.collection