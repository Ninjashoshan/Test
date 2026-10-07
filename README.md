# TwLog 0.1.0

Logs the Twitter app's network and web view activity to the system log, every line prefixed `[TwLog]`.
Built for iPhone 5s, iOS 10.3.3, rootful jailbreak. It changes no behaviour; it only writes log lines.

## Build (GitHub, no Mac needed)
1. Create a free GitHub account, then a new repository (private is fine).
2. Upload everything in this folder, including the hidden `.github` folder.
   If `.github` doesn't upload: Add file > Create new file, type `.github/workflows/build.yml` as the
   name, and paste the contents of that file.
3. Open the Actions tab, enable workflows, pick "Build TwLog", press Run workflow.
4. When it finishes (green tick), open the run and download the `TwLog-deb` artifact. Unzip it to get the .deb.
   If the run fails (red cross), open it, copy the red error text and send it to me.

## Install and test
1. Install the .deb (Filza, or 3uTools), then respring.
2. Keep the TwitterLegacyPatcher installed so TLS works.
3. Force-quit Twitter, start the 3uTools real-time log, open Twitter, try ONE login, then try reset password.
4. Save the log and send it, or filter it for lines containing `[TwLog]`.

## What gets logged
- Requests/responses: method, scheme://host/path, query parameter NAMES, status, error codes
- The first 300 bytes of the body of responses with status 400 or higher (usually the error JSON)
- Redirects, and whether the app cancelled them
- Certificate challenges and what the app answered (disposition 2 = cancelled)
- Web view navigations, responses with status codes, failures

Never logged: query values, request bodies (so not your password), cookies, Authorization headers.
Still skim the log before sharing it.
