import argparse
import string
import secrets
import math
import random

def build_charset(use_lower=True, use_upper=True, use_digits=True, use_punct=True, no_ambig=False):
    sets = []
    if use_lower:
        sets.append(list(string.ascii_lowercase))
    if use_upper:
        sets.append(list(string.ascii_uppercase))
    if use_digits:
        sets.append(list(string.digits))
    if use_punct:
        # Use string.punctuation (can be adjusted if you want fewer symbols)
        sets.append(list(string.punctuation))

    if not sets:
        raise ValueError("At least one character set must be enabled.")

    # merge and optionally filter ambiguous characters
    charset = [c for subset in sets for c in subset]

    if no_ambig:
        ambiguous = set("Il1O0`'\".,;:")  # customizable list
        charset = [c for c in charset if c not in ambiguous]
        # Also remove ambiguous characters from each subset (so required-char guarantee won't pick them)
        sets = [[c for c in subset if c not in ambiguous] for subset in sets]
        # remove any empty subsets (if a subset lost all chars)
        sets = [s for s in sets if s]

    return charset, sets

def generate_password(length=16, use_lower=True, use_upper=True, use_digits=True, use_punct=True, no_ambig=False):
    charset, subsets = build_charset(use_lower, use_upper, use_digits, use_punct, no_ambig)

    if length < len(subsets):
        raise ValueError(f"Length {length} too short to include at least one of each selected set ({len(subsets)} sets).")

    # Guarantee at least one char from each selected subset
    password_chars = [secrets.choice(s) for s in subsets]

    # Fill remaining chars from full charset
    remaining = length - len(password_chars)
    for _ in range(remaining):
        password_chars.append(secrets.choice(charset))

    # Shuffle securely
    sysrand = random.SystemRandom()
    sysrand.shuffle(password_chars)

    password = ''.join(password_chars)
    entropy_bits = estimate_entropy(len(charset), length)
    return password, entropy_bits, len(charset)

def estimate_entropy(charset_size, length):
    # Approximate entropy in bits: length * log2(charset_size)
    if charset_size <= 1:
        return 0.0
    return length * math.log2(charset_size)

def strength_label(bits):
    # Rough categorization (common heuristic)
    if bits < 28:
        return "Very weak"
    if bits < 36:
        return "Weak"
    if bits < 60:
        return "Reasonable"
    if bits < 128:
        return "Strong"
    return "Very strong"

def parse_args():
    p = argparse.ArgumentParser(description="Secure password generator")
    p.add_argument("-l", "--length", type=int, default=16, help="Password length (default 16)")
    p.add_argument("-n", "--number", type=int, default=1, help="Number of passwords to generate")
    p.add_argument("--no-lower", dest="lower", action="store_false", help="Exclude lowercase letters")
    p.add_argument("--no-upper", dest="upper", action="store_false", help="Exclude uppercase letters")
    p.add_argument("--no-digits", dest="digits", action="store_false", help="Exclude digits")
    p.add_argument("--no-punct", dest="punct", action="store_false", help="Exclude punctuation")
    p.add_argument("--no-ambig", dest="no_ambig", action="store_true", help="Remove ambiguous characters (0,O,1,l,I etc)")
    p.add_argument("--show-charset", action="store_true", help="Show final charset used")
    return p.parse_args()

def main():
    args = parse_args()
    try:
        charset, subsets = build_charset(
            use_lower=args.lower,
            use_upper=args.upper,
            use_digits=args.digits,
            use_punct=args.punct,
            no_ambig=args.no_ambig
        )
    except ValueError as e:
        print("Error:", e)
        return

    if args.show_charset:
        print("Charset:", ''.join(sorted(set(charset))))
        print(f"Charset size: {len(set(charset))}")

    for i in range(args.number):
        try:
            pw, bits, cs_size = generate_password(
                length=args.length,
                use_lower=args.lower,
                use_upper=args.upper,
                use_digits=args.digits,
                use_punct=args.punct,
                no_ambig=args.no_ambig
            )
        except ValueError as e:
            print("Error:", e)
            return

        label = strength_label(bits)
        print(f"Password {i+1}: {pw}")
        print(f"  Length: {len(pw)}  Charset size: {cs_size}  Est. entropy: {bits:.1f} bits ({label})")
        print()

if __name__ == "__main__":
    main()
