import sys
import traceback
sys.path.insert(0, ".")
from backend.app import _gemini_chat_stream

try:
    import google.generativeai as genai
    from config import GEMINI_API_KEY, GEMINI_MODEL
    print("API Key:", GEMINI_API_KEY[:5])
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)
    response = model.generate_content("hi", stream=True)
    for chunk in response:
        print("Chunk:", chunk.text)
except Exception as e:
    print("Inner exception:")
    traceback.print_exc()
