# Mobile apps (React Native / Expo / Flutter) and their backends

- **The app bundle is public.** Anyone can unzip an APK/IPA and read strings: `EXPO_PUBLIC_*`, `app.config.js` extras, `.env` values baked in at build, Flutter `--dart-define` values. Secret keys (OpenAI, Stripe secret, Supabase service_role, SMTP) must live on a backend/edge function; the app calls that backend with the user's token.
- **Token storage:** `expo-secure-store` / `react-native-keychain` / Flutter `flutter_secure_storage` (Keychain/Keystore) — not `AsyncStorage`/`SharedPreferences` for refresh tokens.
- **The backend enforces everything** (auth, roles, prices, quotas, validation) — client checks, hidden screens and "premium" flags in the app are bypassable (and jailbroken/rooted devices or a proxy like mitmproxy make it trivial).
- **Deep links / universal links:** validate parameters, never perform state-changing actions straight from a link without confirmation; verify OAuth redirects use the platform's verified app links / PKCE.
- **WebViews:** no `javascriptEnabled` + bridge for untrusted content; restrict `originWhitelist`; don't load user-controlled URLs in a privileged WebView.
- **Network:** HTTPS only (ATS on iOS, `cleartextTrafficPermitted=false` on Android); certificate pinning only if you can manage rotations.
- **Abuse:** rate-limit the API per user/device/IP; Play Integrity / App Attest (or Firebase App Check) to raise the bar for scripts.
- **OTA updates (EAS Update/CodePush):** signed updates, restricted publish credentials.
- **Logs/crash reports:** no tokens or personal data.
- **Store keys:** Apple/Google signing keys and API keys for stores in a password manager/CI secrets with 2FA on developer accounts.
