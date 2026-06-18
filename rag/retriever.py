from rag.playbook_loader import PlaybookLoader


class PlaybookRetriever:
    """
    Given an alert, retrieves the most relevant playbook
    using semantic search (searches by meaning, not keywords).
    """

    def __init__(self):
        loader = PlaybookLoader()
        loader.load_all_playbooks()
        self.collection = loader.get_collection()

    def retrieve(self, alert_description: str, n_results: int = 1) -> str:
        """
        Find the most relevant playbook for this alert.
        Returns the playbook text to feed to the AI agent.
        """
        results = self.collection.query(
            query_texts=[alert_description],
            n_results=n_results
        )

        if results["documents"] and results["documents"][0]:
            playbook_text = results["documents"][0][0]
            playbook_name = results["metadatas"][0][0].get("playbook_name", "unknown")
            print(f"[RAG] Retrieved playbook: {playbook_name}")
            return playbook_text
        else:
            return "No specific playbook found. Follow general incident response procedures."