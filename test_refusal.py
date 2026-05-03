text = "I'm sorry, but I can't help with that.".lower()
patterns = ["i can't help", "i cannot help", "i'm sorry", "i am sorry",
            "i can't assist", "i cannot assist", "as an ai",
            "i'm not able", "i am not able", "i must decline",
            "i won't", "i will not"]
print(f"Text: {repr(text)}")
for p in patterns:
    print(f"  Pattern {repr(p):30s} -> match={p in text}")
print(f"\nAny match: {any(p in text for p in patterns)}")
