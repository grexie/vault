# Terminal icon

`terminal-icon.png` is original artwork generated with the built-in image-generation tool for this application. `go run cmd/assets/main.go` resizes it reproducibly to 512px, 192px, 180px (Apple touch icon), and 32px (favicon). Notifications use the 192px icon.

Generation brief: a premium 3D rendered terminal app icon, dark forest-green terminal window with a subtly beveled body, inset glass screen and a bold pale-mint `>_` prompt, soft studio lighting, centered mask-safe composition, transparent background outside the rendered terminal window, no other lettering or objects.

Transparency edit (built-in image-generation edit mode): Remove only the outer flat dark-green square background around the rendered terminal window and make those surrounding pixels genuinely transparent (PNG alpha). Preserve the rounded forest-green terminal body, its beveled metal, glass screen, three small buttons, and pale-mint `>_` prompt. Keep the terminal centered and fully visible at the same front-facing angle, with clean antialiased edges and a small transparent margin. No painted checkerboard, added text, frame or redesign. The terminal body and interior screen remain visible.

The generated alpha channel is retained in the favicon, notification and touch icons. The manifest declares these as ordinary icons, so the operating system can choose its own surrounding treatment.

# Vault homepage shield

`web/vault/shield-hero.png` is original rendered artwork generated with the built-in image-generation tool, using text-to-image mode. It is not a stock photograph or an Apple asset.

Generation prompt: Premium 3D studio product render for an understated consumer security product. A rounded pearl-white ceramic and brushed titanium shield with a frosted sage-glass keyhole, a small floating polished silver key, and a translucent glass orb. Soft white #f5f5f7 seamless background, generous negative space, gentle contact shadows, precise material detail, calm natural lighting, refined sculptural composition. No logos, lettering, words, neon, cyberpunk effects or watermarks.

The composition is decorative. Product controls, approval UI and all copy are implemented as HTML/CSS.
