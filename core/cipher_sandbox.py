import string
import collections


def caesar_encrypt(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


def caesar_brute_force(ciphertext: str) -> list[dict]:
    results = []
    for shift in range(1, 26):
        decrypted = caesar_decrypt(ciphertext, shift)
        freq = letter_frequency(decrypted)
        chi = chi_squared_english(freq, len([c for c in decrypted if c.isalpha()]))
        results.append({
            "shift": shift,
            "decrypted": decrypted,
            "frequency": freq,
            "chi_squared": round(chi, 4),
        })
    results.sort(key=lambda x: x["chi_squared"])
    return results


ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
    'z': 0.074
}


def letter_frequency(text: str) -> dict:
    text_lower = text.lower()
    total = sum(1 for c in text_lower if c.isalpha())
    if total == 0:
        return {c: 0.0 for c in string.ascii_lowercase}
    counts = collections.Counter(c for c in text_lower if c.isalpha())
    return {c: round((counts.get(c, 0) / total) * 100, 3) for c in string.ascii_lowercase}


def chi_squared_english(freq: dict, total_letters: int) -> float:
    if total_letters == 0:
        return float('inf')
    chi = 0.0
    for letter in string.ascii_lowercase:
        observed = (freq.get(letter, 0) / 100) * total_letters
        expected = (ENGLISH_FREQ[letter] / 100) * total_letters
        if expected > 0:
            chi += ((observed - expected) ** 2) / expected
    return chi


def build_playfair_matrix(keyword: str) -> list[list[str]]:
    keyword = keyword.upper().replace('J', 'I')
    seen = []
    for ch in keyword:
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    for ch in string.ascii_uppercase.replace('J', ''):
        if ch not in seen:
            seen.append(ch)
    matrix = [seen[i * 5:(i + 1) * 5] for i in range(5)]
    return matrix


def _playfair_find(matrix: list[list[str]], ch: str) -> tuple[int, int]:
    for r, row in enumerate(matrix):
        if ch in row:
            return r, row.index(ch)
    raise ValueError(f"Character '{ch}' not found in Playfair matrix.")


def _playfair_prepare_text(text: str) -> list[str]:
    text = text.upper().replace('J', 'I')
    filtered = [c for c in text if c.isalpha()]
    pairs = []
    i = 0
    while i < len(filtered):
        a = filtered[i]
        if i + 1 < len(filtered):
            b = filtered[i + 1]
        else:
            b = 'X'
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs


def playfair_encrypt(plaintext: str, keyword: str) -> str:
    matrix = build_playfair_matrix(keyword)
    pairs = _playfair_prepare_text(plaintext)
    result = []
    for a, b in pairs:
        ra, ca = _playfair_find(matrix, a)
        rb, cb = _playfair_find(matrix, b)
        if ra == rb:
            result.append(matrix[ra][(ca + 1) % 5])
            result.append(matrix[rb][(cb + 1) % 5])
        elif ca == cb:
            result.append(matrix[(ra + 1) % 5][ca])
            result.append(matrix[(rb + 1) % 5][cb])
        else:
            result.append(matrix[ra][cb])
            result.append(matrix[rb][ca])
    return "".join(result)


def playfair_decrypt(ciphertext: str, keyword: str) -> str:
    matrix = build_playfair_matrix(keyword)
    pairs = _playfair_prepare_text(ciphertext)
    result = []
    for a, b in pairs:
        ra, ca = _playfair_find(matrix, a)
        rb, cb = _playfair_find(matrix, b)
        if ra == rb:
            result.append(matrix[ra][(ca - 1) % 5])
            result.append(matrix[rb][(cb - 1) % 5])
        elif ca == cb:
            result.append(matrix[(ra - 1) % 5][ca])
            result.append(matrix[(rb - 1) % 5][cb])
        else:
            result.append(matrix[ra][cb])
            result.append(matrix[rb][ca])
    return "".join(result)
