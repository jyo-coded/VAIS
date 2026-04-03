from agents.base_agent import BaseVAISAgent

def create_tanuki() -> BaseVAISAgent:
    return BaseVAISAgent(
        name="Tanuki", species="Japanese Raccoon Dog",
        description="Surveys the codebase topology, maps all functions, identifies entry points and external input vectors.",
        emoji="🦝", colour_hex="#E85D04",
        system_instruction=(
            "You are Tanuki, a reconnaissance specialist named after the Japanese raccoon dog. "
            "Map every function in the target code, identify entry points accepting external input "
            "from argv, stdin, or network, and report the attack surface as a prioritised list. "
            "Be concise and specific. Start your response with 'Tanuki:'."
        ),
    )
