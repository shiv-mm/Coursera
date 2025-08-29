# Text CAPTCHA 
import random
import string

# Exclude ambiguous characters to reduce confusion: 0/O and 1/I
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CAPTCHA_LEN = 6

QUOTES = [
    "What you seek is seeking you. — Rumi",
    "Act as if what you do makes a difference. It does. — William James",
    "In the middle of difficulty lies opportunity. — Albert Einstein",
    "We are what we repeatedly do. Excellence, then, is not an act, but a habit. — Will Durant",
    "The only impossible journey is the one you never begin. — Tony Robbins",
    "If you want to go far, go together. — African Proverb",
    "The future depends on what you do today. — Mahatma Gandhi",
    "Stars can’t shine without darkness. — D.H. Sidebottom",
    "Keep your face always toward the sunshine—and shadows will fall behind you. — Walt Whitman",
    "Courage is grace under pressure. — Ernest Hemingway",
]

def generate_captcha(n: int = CAPTCHA_LEN) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(n))

def display_captcha(code: str) -> None:
    # Simple readable framing with spaced characters
    spaced = " ".join(code)
    bar = "─" * (len(spaced) + 2)
    print()
    print(f"╭{bar}╮")
    print(f"│ {spaced} │")
    print(f"╰{bar}╯")
    print("Enter the 6-character CAPTCHA exactly as shown (case-sensitive).")

def run_captcha_loop():
    while True:
        code = generate_captcha()
        display_captcha(code)
        user = input("Your input (or 'q' to quit): ").strip()
        if user.lower() == "q":
            print("Exited. No verification performed.")
            break
        if user == code:
            quote = random.choice(QUOTES)
            print("\n✅ Verified! Here's a beautiful thought for you:")
            print(f"“{quote}”")
            break
        else:
            print("\n❌ Incorrect. Generating a new CAPTCHA... try again.\n")

if __name__ == "__main__":
    run_captcha_loop()
