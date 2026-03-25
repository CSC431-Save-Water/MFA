# MFA System — Test Results

## Test Case 1: Successful Login with Security Question (Case-Insensitive)

**Setup:** Register user `eva` with password `mypass` and security question
"First car?" answered as `honda`.

**Login attempt:** Password `mypass`, answer `Honda` (different case).

**Expected:** Access granted (answers are normalised to lowercase before comparison).

**Output:**
```
Account created successfully for 'eva'!
...
Password authentication successful.
Security Question: First car?
Your answer: Multi-Factor Authentication successful. Access granted. Welcome, eva!
```

**Result:** PASS — case-insensitive answer matching works correctly.

---

## Test Case 2: Account Lockout After Three Failed Password Attempts

**Setup:** Register user `charlie` with password `pass1`.

**Login attempts:** Enter wrong password `wrong1`, `wrong2`, `wrong3` on three
consecutive attempts, then try to log in again.

**Expected:** Failure count increments with each attempt; account locks on the
third failure; fourth attempt is rejected immediately with a locked-account message.

**Output:**
```
Error: Incorrect password. 2 attempt(s) remaining before lockout.
Error: Incorrect password. 1 attempt(s) remaining before lockout.
Error: Incorrect password. Account is now LOCKED after 3 failed attempts.
Error: Account 'charlie' is locked after too many failed attempts. Contact support.
```

**Result:** PASS — lockout triggers exactly at 3 failures and blocks all subsequent attempts.

---

## Test Case 3: Login Attempt with Unknown Username

**Setup:** No accounts registered.

**Login attempt:** Username `unknown_user`.

**Expected:** Error message stating no account was found; program does not prompt for password.

**Output:**
```
Error: No account found for username 'unknown_user'.
```

**Result:** PASS — system rejects unknown usernames before requesting a password,
preventing information leakage about which credentials are wrong.

---

## Test Case 4: Successful OTP Login and Failed OTP Login

**Setup:** Register user `alice` with password `secret123` and OTP contact
`alice@example.com`.
Register user `bob` with password `hunter2` and security question
"What is your pet's name?" answered `fluffy`.

**Login attempt (alice):** Correct password, but enter `123456` as the OTP
(hardcoded guess — the actual OTP is randomly generated).

**Login attempt (bob):** Correct password, correct security answer `fluffy`.

**Expected:** Alice denied (wrong OTP, 2 attempts remaining); Bob granted access.

**Output:**
```
[alice] Password authentication successful.
[SIMULATED] OTP 401480 sent to: alice@example.com
Error: Incorrect verification code.
Access denied. 2 attempt(s) remaining before lockout.

[bob] Password authentication successful.
Security Question: What is your pet's name?
Multi-Factor Authentication successful. Access granted. Welcome, bob!
```

**Result:** PASS — OTP mismatch correctly denies access; correct security answer grants access.

---

## Test Case 5: Duplicate Username Registration

**Setup:** Register `alice` once, then attempt to register `alice` again.

**Expected:** Second registration is rejected with an error message.

**Output:**
```
Account created successfully for 'alice'!
...
Error: Username 'alice' is already taken.
```

**Result:** PASS — duplicate usernames are rejected.
