# VLESS to sing-box

Static browser-only converter for GitHub Pages.

## Deploy to GitHub Pages

1. Put `index.html` and `converter.js` in the published folder.
2. In repository settings, enable Pages for that folder or for the branch root.
3. Open the Pages URL. No server, build step, API, or external CDN is required.

The app converts multiple `vless://` links into one sing-box JSON config with `urltest`, and can convert sing-box VLESS outbounds back to links.
