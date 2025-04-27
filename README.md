# cert-create

This is the original code for what became **certM3**.

- It does **not** do any user ID validation, but it may still be handy to create certs in your closed system where you know your users.
- It retains the essential feature of keeping the **private key local to the user's browser**.
- You can examine the JavaScript code to ensure that the `private_key` never gets sent over the wire.
- If you need a full featured user/group/(user) certificate manager, see certM3.
- Uses the following, and is not designed to swap out components.
-- Loopback4
-- NodeJS
-- Nginx
-- PostgreSQL

Use this as a reference or utility for browser-based certificate creation in trusted environments. 
