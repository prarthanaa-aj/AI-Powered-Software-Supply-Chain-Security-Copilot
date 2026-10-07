import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("VOC_API_KEY")

if not api_key:
    print("❌ API key not found.")
    exit()

print("✓ API key found")

client = OpenAI(
    api_key=api_key,
    base_url="https://openai.vocareum.com/v1"
)

try:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "user",
                "content": "Reply with: Vocareum API is working."
            }
        ],
        max_tokens=50
    )

    print("✓ API connection successful")
    print("✓ Model response:")
    print(response.choices[0].message.content)

except Exception as e:
    print("❌ API request failed")
    print(type(e).__name__)
    print(e)