# Blinder artwork

The mark is a redacted empty set: a circle and slash, interrupted by a horizontal bar. It pairs a minimal nihilist motif with Blinder's purpose of reducing exposed identity. The wordmark is original geometric SVG lettering; it needs no installed font.

![Blinder header](assets/blinder-header.svg)

| Asset | Use | Size |
| --- | --- | --- |
| [Header](assets/blinder-header.svg) | README and documentation header | 1280 × 420 SVG |
| [Project mark](assets/blinder-mark.svg) | Scalable project icon | 512 × 512 SVG |
| [Avatar](assets/blinder-avatar.png) | Uploadable project/profile icon | 1024 × 1024 PNG |
| [Social preview](assets/blinder-social.png) | Repository social preview and link cards | 1280 × 640 PNG |
| [Social source](assets/blinder-social.svg) | Editable social-preview artwork | 1280 × 640 SVG |

## Palette and treatment

- Near-black: `#111210`.
- Warm ivory: `#EEEAE0`.
- Secondary text: `#AAA99F`.
- Rules: `#35362F`.

Keep the dark field and generous clear space around the mark. Use flat colours; avoid gradients, shadows and decorative effects. The header/social SVGs use a system monospace stack for small descriptive text. Primary lettering and the project mark are vector paths; no external resources or scripts are loaded.

PNG exports are ready to upload. They have not been applied to GitHub repository or organisation settings.

To regenerate the PNGs after editing the SVG sources, using `rsvg-convert`:

```sh
rsvg-convert -w 1024 -h 1024 docs/assets/blinder-mark.svg -o docs/assets/blinder-avatar.png
rsvg-convert docs/assets/blinder-social.svg -o docs/assets/blinder-social.png
```
