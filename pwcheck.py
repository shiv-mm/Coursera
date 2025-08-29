# password_strength.py
from dataclasses import dataclass
from collections import Counter
import unicodedata

@dataclass
class Metrics:
    length: int = 0
    words: int = 0
    letters: int = 0
    uppercase: int = 0
    lowercase: int = 0
    digits: int = 0
    symbols: int = 0
    spaces: int = 0

def is_symbol(ch: str) -> bool:
    # Treat Unicode punctuation/symbols as symbols
    cat = unicodedata.category(ch)
    return cat[0] in {"P", "S"}

def count_words(s: str) -> int:
    # Simple whitespace-delimited word count (handles multiple spaces/tabs/newlines)
    return len(s.split())

def measure(pw: str) -> Metrics:
    m = Metrics()
    pw = pw.rstrip("\n\r")
    m.length = len(pw)
    m.words = count_words(pw)
    for ch in pw:
        if ch.isalpha():
            m.letters += 1
            if ch.isupper():
                m.uppercase += 1
            elif ch.islower():
                m.lowercase += 1
        elif ch.isdigit():
            m.digits += 1
        elif ch.isspace():
            m.spaces += 1
        elif is_symbol(ch):
            m.symbols += 1
        else:
            # Any other characters (e.g., marks) are counted as symbols for strength purposes
            m.symbols += 1
    return m

def clamp(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, x))

def repeat_penalty(pw: str) -> int:
    # Penalize repeated characters; up to -20
    freq = Counter(pw)
    repeats = sum(max(0, c - 1) for c in freq.values())
    penalty = min(20, repeats * 2)
    return penalty

def sequence_penalty_alpha(pw: str) -> int:
    # Penalize ascending alphabetic runs (abc, wxyz); cap -20
    n = len(pw)
    penalty = 0
    i = 0
    while i < n:
        run = 1
        j = i
        while j + 1 < n:
            c1 = pw[j].lower()
            c2 = pw[j + 1].lower()
            if ("a" <= c1 <= "z") and ("a" <= c2 <= "z") and (ord(c2) == ord(c1) + 1):
                run += 1
                j += 1
            else:
                break
        if run >= 3:
            penalty += 5 + (run - 3) * 2
            i = j + 1
        else:
            i += 1
    return min(20, penalty)

def sequence_penalty_digit(pw: str) -> int:
    # Penalize ascending digit runs (123, 4567); cap -20
    n = len(pw)
    penalty = 0
    i = 0
    while i < n:
        run = 1
        j = i
        while j + 1 < n:
            c1 = pw[j]
            c2 = pw[j + 1]
            if c1.isdigit() and c2.isdigit() and (ord(c2) == ord(c1) + 1):
                run += 1
                j += 1
            else:
                break
        if run >= 3:
            penalty += 5 + (run - 3) * 2
            i = j + 1
        else:
            i += 1
    return min(20, penalty)

def compute_score(m: Metrics, pw: str) -> int:
    score = 0

    # Length contribution (max 60)
    length_score = m.length * 3
    score += min(60, length_score)

    # Variety contribution (max 40)
    variety = 0
    if m.lowercase > 0: variety += 10
    if m.uppercase > 0: variety += 10
    if m.digits   > 0: variety += 10
    if m.symbols  > 0: variety += 10
    score += variety

    # Penalties for single-type passwords
    if m.letters > 0 and m.digits == 0 and m.symbols == 0:
        score -= 15  # only letters
    if m.digits > 0 and m.letters == 0 and m.symbols == 0:
        score -= 15  # only digits

    # Pattern penalties
    score -= repeat_penalty(pw)
    score -= sequence_penalty_alpha(pw)
    score -= sequence_penalty_digit(pw)

    # Discourage trivial passphrases (many spaces with no symbols)
    if m.spaces >= 3 and m.symbols == 0:
        score -= 5

    return clamp(score, 0, 100)

def verdict(score: int) -> str:
    if score < 25: return "Very Weak"
    if score < 50: return "Weak"
    if score < 70: return "Moderate"
    if score < 85: return "Strong"
    return "Very Strong"

def feedback(m: Metrics, pw: str) -> list[str]:
    tips = []
    rep_pen = repeat_penalty(pw)
    alpha_seq_pen = sequence_penalty_alpha(pw)
    digit_seq_pen = sequence_penalty_digit(pw)

    if m.length < 12:
        tips.append("Use at least 12–16 characters or a 4–5 word passphrase of uncommon words.")
    if m.uppercase == 0:
        tips.append("Add uppercase letters (A–Z).")
    if m.lowercase == 0:
        tips.append("Add lowercase letters (a–z).")
    if m.digits == 0:
        tips.append("Include digits (0–9).")
    if m.symbols == 0:
        tips.append("Include symbols (e.g., ! @ # $ %).")
    if m.letters > 0 and m.digits == 0 and m.symbols == 0:
        tips.append("Avoid only letters — mix in digits and symbols.")
    if m.digits > 0 and m.letters == 0 and m.symbols == 0:
        tips.append("Avoid only digits — add letters and symbols.")
    if rep_pen > 0:
        tips.append("Avoid repeating characters (e.g., aaa, 1111).")
    if alpha_seq_pen > 0 or digit_seq_pen > 0:
        tips.append("Avoid obvious sequences (abc, 1234).")
    if m.spaces >= 3 and m.symbols == 0:
        tips.append("If using a passphrase, separate words with uncommon separators or add symbols.")
    return tips

def analyze_password(pw: str) -> dict:
    m = measure(pw)
    score = compute_score(m, pw)
    return {
        "metrics": m,
        "score": score,
        "strength": verdict(score),
        "suggestions": feedback(m, pw)
    }

def print_report(result: dict) -> None:
    m: Metrics = result["metrics"]
    print("\n=== Password Analysis ===")
    print(f"Length:    {m.length}")
    print(f"Words:     {m.words}")
    print(f"Letters:   {m.letters} (Uppercase: {m.uppercase}, Lowercase: {m.lowercase})")
    print(f"Digits:    {m.digits}")
    print(f"Symbols:   {m.symbols}")
    print(f"Spaces:    {m.spaces}")
    print(f"Score:     {result['score']} / 100")
    print(f"Strength:  {result['strength']}")
    if result["suggestions"]:
        print("\nSuggestions:")
        for s in result["suggestions"]:
            print(f"- {s}")

if __name__ == "__main__":
    try:
        # Simple interactive prompt; press Enter on empty line to stop
        while True:
            pw = input("Enter password (blank to exit): ")
            if pw == "":
                break
            print_report(analyze_password(pw))
            print()
    except KeyboardInterrupt:
        pass
