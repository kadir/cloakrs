"""Offline cloakrs demo. All inputs and the simulated model response are fictional.

Install: python -m pip install --only-binary=:all: 'cloakrs==0.1.0a2'
Run:     python bindings/python/examples/quickstart.py
"""

from cloakrs import Sanitizer, Scanner


def main() -> None:
    scanner = Scanner(locale="us")
    log = "Contact: jane@example.com"
    masked = scanner.mask(log)
    assert masked == "Contact: [EMAIL]"
    print("Masked log:", masked)

    quoted = "INSERT INTO users VALUES ('jane@example.com');"
    assert scanner.mask(quoted) == "INSERT INTO users VALUES ('[EMAIL]');"
    print("Masked raw text:", scanner.mask(quoted))

    prompt = "Draft a reply to jane@example.com about the delayed delivery."
    clean, mapping = Sanitizer(locale="us").sanitize(prompt)
    assert clean == "Draft a reply to [EMAIL_1] about the delayed delivery."
    print("Sanitized prompt:", clean)

    # A real application would send only clean to its chosen model, keeping
    # mapping local. This example makes no model call or network request.
    simulated_response = "Reply to [ email_1 ]: Your delivery is delayed."
    restored = mapping.restore(simulated_response)
    assert restored == "Reply to jane@example.com: Your delivery is delayed."
    print("Restored simulated reply:", restored)

    # Mapping contains original values. Never send it with the sanitized prompt
    # or log mapping.to_json(). Restored output also contains the originals.
    print("Alpha: check detection on representative data before adoption.")


if __name__ == "__main__":
    main()
