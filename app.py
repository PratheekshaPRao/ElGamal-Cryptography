from flask import Flask, jsonify, render_template, request
import secrets

app = Flask(__name__)

# Keeps generator search and factorization responsive for a college lab.
MAX_PRIME = 1_000_000_000


def is_prime(n):
    """Deterministic Miller–Rabin primality test for n < 2^64."""
    if n < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    # Write n - 1 as d * 2^s, with d odd.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # These bases make Miller–Rabin deterministic for all n < 2^64.
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % n == 0:
            continue

        value = pow(base, d, n)
        if value in (1, n - 1):
            continue

        for _ in range(s - 1):
            value = pow(value, 2, n)
            if value == n - 1:
                break
        else:
            return False

    return True


def distinct_prime_factors(n):
    """Return the distinct prime factors of n."""
    factors = []
    divisor = 2

    while divisor * divisor <= n:
        if n % divisor == 0:
            factors.append(divisor)
            while n % divisor == 0:
                n //= divisor
        divisor = 3 if divisor == 2 else divisor + 2

    if n > 1:
        factors.append(n)

    return factors


def find_generator(p):
    """Find a primitive root modulo prime p."""
    factors = distinct_prime_factors(p - 1)

    for g in range(2, p):
        if all(pow(g, (p - 1) // factor, p) != 1 for factor in factors):
            return g

    raise ValueError("Could not find a generator for this prime.")


def read_prime(data):
    try:
        p = int(data.get("p", ""))
    except (TypeError, ValueError):
        raise ValueError("Enter p as a whole number.")

    if p <= 255:
        raise ValueError("p must be greater than 255 so it can represent ASCII values.")
    if p > MAX_PRIME:
        raise ValueError(f"For this lab, p must not exceed {MAX_PRIME:,}.")
    if not is_prime(p):
        raise ValueError("p must be a prime number.")

    return p


def read_int(data, field):
    try:
        return int(data[field])
    except (KeyError, TypeError, ValueError):
        raise ValueError(f"Missing or invalid value for {field}.")


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/keygen")
def keygen():
    try:
        data = request.get_json(force=True)
        p = read_prime(data)
        g = find_generator(p)

        # The assignment specifies 2 <= x <= p - 2.
        x = secrets.randbelow(p - 3) + 2
        y = pow(g, x, p)

        return jsonify({
            "p": p,
            "g": g,
            "x": x,
            "y": y,
            "steps": [
                f"Validated p = {p}: it is prime and greater than 255.",
                f"Factored p − 1 = {p - 1}; its distinct prime factors are "
                f"{distinct_prime_factors(p - 1)}.",
                f"Selected generator g = {g}, a primitive root modulo p.",
                f"Generated private key x = {x}, where 2 ≤ x ≤ p − 2.",
                f"Calculated public key y = g^x mod p = {g}^{x} mod {p} = {y}.",
            ],
        })
    except ValueError as error:
        return jsonify({"error": str(error)}), 400


@app.post("/api/encrypt")
def encrypt():
    try:
        data = request.get_json(force=True)
        p = read_prime(data)
        g = read_int(data, "g")
        y = read_int(data, "y")
        message = data.get("message")

        if not isinstance(message, str) or not message:
            raise ValueError("Enter a message before encrypting.")
        if len(message) > 500:
            raise ValueError("Messages are limited to 500 characters.")
        if not (2 <= g <= p - 2) or not (1 <= y < p):
            raise ValueError("The supplied public key values are invalid.")

        # The assignment specifies 2 <= k <= p - 2.
        k = secrets.randbelow(p - 3) + 2
        c1 = pow(g, k, p)
        shared_key = pow(y, k, p)

        character_steps = []
        c2_values = []

        for character in message:
            m = ord(character)
            if m >= p:
                raise ValueError(
                    f"The character {character!r} has code point {m}, which "
                    f"is not less than p. Use a larger valid p or a different message."
                )

            c2 = (m * shared_key) % p
            c2_values.append(c2)
            character_steps.append({
                "character": character,
                "ascii": m,
                "calculation": f"({m} × {shared_key}) mod {p} = {c2}",
                "c2": c2,
            })

        return jsonify({
            "p": p,
            "g": g,
            "y": y,
            "message": message,
            "k": k,
            "c1": c1,
            "shared_key": shared_key,
            "c2_values": c2_values,
            "ciphertext": {"c1": c1, "c2": c2_values},
            "character_steps": character_steps,
            "steps": [
                f"Generated random encryption key k = {k}, where 2 ≤ k ≤ p − 2.",
                f"Calculated c1 = g^k mod p = {g}^{k} mod {p} = {c1}.",
                f"Calculated shared key = y^k mod p = {y}^{k} mod {p} = {shared_key}.",
                "For each character, calculated c2 = (ASCII value × shared key) mod p.",
            ],
        })
    except ValueError as error:
        return jsonify({"error": str(error)}), 400


@app.post("/api/decrypt")
def decrypt():
    try:
        data = request.get_json(force=True)
        p = read_prime(data)
        x = read_int(data, "x")
        c1 = read_int(data, "c1")
        c2_values = data.get("c2_values")

        if not (2 <= x <= p - 2):
            raise ValueError("The supplied private key is invalid.")
        if not (1 <= c1 < p):
            raise ValueError("The supplied c1 value is invalid.")
        if not isinstance(c2_values, list) or not c2_values:
            raise ValueError("No ciphertext values were supplied.")

        encrypted_shared_key = pow(c1, x, p)
        inverse = pow(encrypted_shared_key, -1, p)
        recovered_characters = []
        character_steps = []

        for index, value in enumerate(c2_values):
            if not isinstance(value, int) or not (0 <= value < p):
                raise ValueError(f"Ciphertext value at position {index + 1} is invalid.")

            m = (value * inverse) % p
            character = chr(m)
            recovered_characters.append(character)
            character_steps.append({
                "c2": value,
                "ascii": m,
                "character": character,
                "calculation": f"({value} × {inverse}) mod {p} = {m}",
            })

        message = "".join(recovered_characters)

        return jsonify({
            "p": p,
            "x": x,
            "c1": c1,
            "shared_key": encrypted_shared_key,
            "inverse": inverse,
            "message": message,
            "character_steps": character_steps,
            "steps": [
                f"Calculated shared key = c1^x mod p = {c1}^{x} mod {p} "
                f"= {encrypted_shared_key}.",
                f"Calculated modular inverse = shared key⁻¹ mod p "
                f"= {inverse}, because ({encrypted_shared_key} × {inverse}) mod {p} = 1.",
                "For each ciphertext value, calculated "
                "m = (c2 × shared key⁻¹) mod p, then converted m back to a character.",
            ],
        })
    except ValueError as error:
        return jsonify({"error": str(error)}), 400


if __name__ == "__main__":
    app.run(debug=True)
