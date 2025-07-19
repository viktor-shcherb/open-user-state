## Secure PAT Handling on the Frontend

The frontend never stores the Personal Access Token in `localStorage` or any
other JavaScript accessible storage. After the user supplies the token it must
be sent once over HTTPS via a POST to `/api/token`. The Worker encrypts the
value at rest using AES-GCM, providing confidentiality and integrity. Display a
notice in the UI: "Your token is encrypted at rest with AES-GCM (confidentiality
+ integrity)." You may remove the token later by sending a `DELETE /api/token`
request.

Invalid user input results in `400 Bad Request`. If decryption or authentication
fails the worker responds with `401 Unauthorized`. Any server error returns
`500`, prompting the user to retry later. Rotate your PAT periodically and
submit it again through this flow.
