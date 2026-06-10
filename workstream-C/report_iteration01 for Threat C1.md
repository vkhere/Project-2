### Threat Card C1 – Theft of stored card and address data

- Attacker:
  - Authenticated Juice Shop user who finds a vulnerability (e.g., SQL injection, IDOR, auth bypass), or
  - External attacker who first compromises an account (weak login, no lockout) and then pivots.

- Entry points:
  - Web: `http://192.168.1.104:3000/#/account`, `#/address`, `#/saved-payment-methods`
  - APIs: `GET /api/Address/`, `GET /api/Cards/` (or similar paths seen in Burp)

- Assets at risk:
  - Stored card details (even test data stands in for real PAN/expiry).
  - Home and billing addresses.
  - Linked account identity (name, email, phone).

 
## B1 – Weak authentication / no lockout

Attack: credential stuffing or brute force to take over many user accounts and read their stored cards/addresses.
Evidence: you tried multiple bad passwords and never saw lockout or CAPTCHA on /rest/user/login.

## B2 – IDOR / Broken Access Control

Attack: change an ID in a URL or API body to retrieve someone else’s address or card.
Evidence: in Burp Repeater you change userId or addressId and the API returns another user’s record.

## B3 – Injection / XSS

Attack: use SQLi or XSS to extract or exfiltrate stored card data.
Evidence: DVWA or Juice Shop endpoint where you’ve already proven SQLi or powerful XSS.



## Summary:
- C1 is enabled by:
  - B1 (weak login) → easier account takeover at scale.
  - B2 (IDOR on /api/Address) → direct cross-account read of addresses.
  - B3 (SQLi in profile lookup) → backend dump of card table.
