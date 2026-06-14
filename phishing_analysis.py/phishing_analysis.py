import re

# List of common phishing keywords
PHISHING_KEYWORDS = [
    "urgent",
    "verify",
    "password",
    "login",
    "account suspended",
    "click here",
    "bank",
    "security alert",
    "update",
    "immediately",
    "reward",
    "prize",
    "won"
]


def analyze_message(message):

    red_flags = []

    found_keywords = []

    # Find suspicious keywords
    for keyword in PHISHING_KEYWORDS:
        if keyword.lower() in message.lower():
            found_keywords.append(keyword)

    if found_keywords:
        red_flags.append("Suspicious Keywords Found")

    # Find URLs
    urls = re.findall(r'https?://[^\s]+', message)

    suspicious_links = []

    trusted_domains = [
        "google.com",
        "microsoft.com",
        "amazon.com",
        "github.com"
    ]

    for url in urls:

        trusted = False

        for domain in trusted_domains:
            if domain in url:
                trusted = True

        if not trusted:
            suspicious_links.append(url)

    if suspicious_links:
        red_flags.append("Suspicious Links Detected")

    # Urgency detection
    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "verify now"
    ]

    for word in urgency_words:
        if word.lower() in message.lower():
            red_flags.append("Creates Sense of Urgency")
            break

    return {
        "keywords": found_keywords,
        "links": urls,
        "flags": red_flags
    }


def main():

    try:
        with open("sample_emails.txt", "r", encoding="utf-8") as file:
            content = file.read()

    except FileNotFoundError:
        print("sample_emails.txt not found.")
        return

    emails = content.split("==================================================")

    report_file = open("report.txt", "w", encoding="utf-8")

    print("\nPHISHING AWARENESS ANALYSIS")
    print("=" * 50)

    report_file.write("PHISHING AWARENESS ANALYSIS\n")
    report_file.write("=" * 50 + "\n\n")

    email_count = 1

    for email in emails:

        if email.strip() == "":
            continue

        result = analyze_message(email)

        print(f"\nEMAIL {email_count}")
        print("-" * 30)

        report_file.write(f"\nEMAIL {email_count}\n")
        report_file.write("-" * 30 + "\n")

        print("Keywords Found:")
        report_file.write("Keywords Found:\n")

        if result["keywords"]:
            for keyword in result["keywords"]:
                print("•", keyword)
                report_file.write(f"• {keyword}\n")
        else:
            print("None")
            report_file.write("None\n")

        print("\nLinks Found:")
        report_file.write("\nLinks Found:\n")

        if result["links"]:
            for link in result["links"]:
                print("•", link)
                report_file.write(f"• {link}\n")
        else:
            print("No Links")
            report_file.write("No Links\n")

        print("\nRed Flags:")
        report_file.write("\nRed Flags:\n")

        if result["flags"]:
            for flag in result["flags"]:
                print("•", flag)
                report_file.write(f"• {flag}\n")
        else:
            print("No Red Flags")
            report_file.write("No Red Flags\n")

        print("\nWhy Unsafe?")
        report_file.write("\nWhy Unsafe?\n")

        if result["flags"]:
            explanation = (
                "This message contains phishing indicators such as "
                "suspicious keywords, suspicious links, or urgency tactics. "
                "Such messages may attempt to steal personal information."
            )

            print(explanation)
            report_file.write(explanation + "\n")
        else:
            print("No significant phishing indicators detected.")
            report_file.write(
                "No significant phishing indicators detected.\n"
            )

        email_count += 1

    report_file.close()

    print("\nAnalysis completed.")
    print("Report saved as report.txt")


if __name__ == "__main__":
    main()