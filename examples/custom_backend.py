"""Copy this interface to integrate another model SDK or local inference engine.

This skeleton intentionally raises until you connect a real text generator;
it must never return an empty successful review as a placeholder.
"""
from agenticbughunter.llm import LLMResponse


class CustomBackend:
    """An application-owned text backend, independent of native tool calling."""

    def chat(self, messages, *, temperature=None, max_tokens=None, metadata=None):
        """Generate text JSON actions/finals from the ordinary chat messages."""
        raise NotImplementedError('Connect your model here and return LLMResponse with final answer text')
