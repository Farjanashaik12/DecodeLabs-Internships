import re

def check_password_strength(password):

    length = len(password)

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

    score = 0

    if length >= 8:
        score += 1

    if has_upper:
        score += 1

    if has_lower:
        score += 1

    if has_digit:
        score += 1

    if has_symbol:
        score += 1

    if score <= 2:
        strength = "WEAK"

    elif score <= 4:
        strength = "MEDIUM"

    else:
        strength = "STRONG"

    return {
        "length": length,
        "uppercase": has_upper,
        "lowercase": has_lower,
        "digit": has_digit,
        "symbol": has_symbol,
        "strength": strength
    }


def main():

    try:
        with open("passwords.txt", "r") as file:
            passwords = file.readlines()

    except FileNotFoundError:
        print("passwords.txt not found")
        return

    report = open("report.txt", "w")

    print("\nPASSWORD STRENGTH CHECKER")
    print("=" * 50)

    report.write("PASSWORD STRENGTH CHECKER\n")
    report.write("=" * 50 + "\n\n")

    for password in passwords:

        password = password.strip()

        if not password:
            continue

        result = check_password_strength(password)

        print(f"\nPassword: {password}")
        print("-" * 30)

        print("Length:", result["length"])
        print("Uppercase:", result["uppercase"])
        print("Lowercase:", result["lowercase"])
        print("Numbers:", result["digit"])
        print("Symbols:", result["symbol"])

        print("Strength:", result["strength"])

        report.write(f"Password: {password}\n")
        report.write(f"Length: {result['length']}\n")
        report.write(f"Uppercase: {result['uppercase']}\n")
        report.write(f"Lowercase: {result['lowercase']}\n")
        report.write(f"Numbers: {result['digit']}\n")
        report.write(f"Symbols: {result['symbol']}\n")
        report.write(f"Strength: {result['strength']}\n")
        report.write("-" * 40 + "\n")

    report.close()

    print("\nAnalysis Complete.")
    print("Report saved as report.txt")


if __name__ == "__main__":
    main()