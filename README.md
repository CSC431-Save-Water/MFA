# Multi-Factor Authentication System

A Java implementation of a simplified Multi-Factor Authentication (MFA) system
that combines password-based login with a secondary verification factor.

---

## How to Run

### Requirements
- Java Development Kit (JDK) 17 or later
- No third-party libraries required — only the Java standard library is used

### Compile
```bash
cd src
javac Account.java MFA.java Main.java
```

### Run
```bash
java Main
```

The program presents an interactive menu:
```
0 - Exit
1 - Register
2 - Log In
```

---

## Features

### User Registration
Users register with a username and password, then choose one of two secondary
authentication factors:
- **OTP** — provide a phone number or email address; a 6-digit code will be
  "sent" there at each login (simulated in the console).
- **Security Question** — provide a question and answer stored securely.

### Password Security
Passwords are never stored in plaintext. Each password is hashed using
**SHA-256** combined with a **unique random salt** (16 bytes via `SecureRandom`).
The salt prevents rainbow-table attacks: two users with the same password will
have different stored hashes. Security question answers are also hashed with the
same salt. Answer comparison is case- and whitespace-insensitive.

### Two-Factor Login
1. **Factor 1 — Password:** the entered password is hashed and compared to the
   stored hash.
2. **Factor 2 — OTP or Security Question:** only reached after factor 1 passes.
   - OTP: a fresh random 6-digit code is generated and printed to the console as
     a simulated delivery, then the user must enter it.
   - Security Question: the user answers the question they set at registration.

Access is granted only when both factors succeed.

### Account Lockout
After **3 consecutive failed login attempts** (wrong password or wrong secondary
factor), the account is locked. Locked accounts cannot be accessed until support
intervenes (reset by modifying or deleting `users.dat`).

### Error Handling
- Unknown username: rejected before a password is requested.
- Duplicate username: rejected at registration.
- Empty username, password, or contact info: rejected with a clear message.
- Failed OTP or security answer: counted toward lockout with attempts-remaining
  shown.

---

## Optional Enhancement: File Persistence (Extra Credit)

Account data is automatically saved to **`users.dat`** in the working directory
after every registration and every login attempt. When the program starts it
loads that file, so accounts survive between sessions.

Each line in `users.dat` holds one account's fields (username, hashed password,
salt, secondary factor type, contact, security question, hashed answer, failed
attempts, locked flag) separated by `|||`.

To reset all accounts, delete `users.dat`.

---

## Dependencies

None. The project uses only Java SE standard library classes:
- `java.security.MessageDigest` — SHA-256 hashing
- `java.security.SecureRandom` — cryptographically random salt generation
- `java.util.Base64` — salt encoding
- `java.io.*` — file persistence
- `java.util.Scanner`, `java.util.HashMap`, `java.util.Random`

---

## Files

| File | Description |
|------|-------------|
| `src/Account.java` | User account model — credentials, secondary factor, lockout state |
| `src/MFA.java` | Core MFA logic — registration, login, OTP generation, file I/O |
| `src/Main.java` | Entry point — interactive menu |
| `TestResults.md` | Five documented test cases with inputs and expected outputs |
| `users.dat` | Auto-generated at runtime — persisted account data |
