/**
 * WCAG 2 contrast of every visible text run on the page against the background it is drawn on.
 * The background is the composite of every translucent ancestor background over the first
 * opaque one (the page background at worst), so tinted badges and callouts are measured as
 * drawn. Text in disabled or translucent controls, visually hidden text and placeholders are
 * exempt, as WCAG exempts them. SVG text is measured by its fill.
 */
import type { Page } from "@playwright/test";

export type ContrastProblem = {
  text: string;
  ratio: number;
  required: number;
  color: string;
  background: string;
};

export async function contrastProblems(page: Page): Promise<ContrastProblem[]> {
  return page.evaluate(() => {
    type RGBA = { r: number; g: number; b: number; a: number };
    const parse = (value: string): RGBA | null => {
      const match = value.match(/rgba?\(([^)]+)\)/);
      if (!match) return null;
      const [r, g, b, a] = match[1]
        .split(/[\s,/]+/)
        .filter(Boolean)
        .map(Number);
      return { r, g, b, a: Number.isFinite(a) ? a : 1 };
    };
    const over = (top: RGBA, bottom: RGBA): RGBA => ({
      r: top.r * top.a + bottom.r * (1 - top.a),
      g: top.g * top.a + bottom.g * (1 - top.a),
      b: top.b * top.a + bottom.b * (1 - top.a),
      a: 1,
    });
    const luminance = ({ r, g, b }: RGBA) => {
      const channel = (value: number) => {
        const v = value / 255;
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
    };
    const ratio = (a: RGBA, b: RGBA) => {
      const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
      return (light + 0.05) / (dark + 0.05);
    };
    const background = (element: Element): RGBA => {
      const layers: RGBA[] = [];
      for (
        let node: Element | null = element;
        node;
        node = node.parentElement
      ) {
        const color = parse(getComputedStyle(node).backgroundColor);
        if (color && color.a > 0) {
          layers.push(color);
          if (color.a >= 1) break;
        }
      }
      let result: RGBA = { r: 255, g: 255, b: 255, a: 1 };
      for (const layer of layers.reverse()) result = over(layer, result);
      return result;
    };
    const exempt = (element: Element) => {
      for (
        let node: Element | null = element;
        node;
        node = node.parentElement
      ) {
        const style = getComputedStyle(node);
        if (Number(style.opacity) < 1) return true;
        if (style.visibility === "hidden" || style.display === "none")
          return true;
        if (
          style.position === "absolute" &&
          (style.clip === "rect(0px, 0px, 0px, 0px)" ||
            style.clipPath === "inset(50%)")
        )
          return true;
        if ((node as HTMLButtonElement).disabled) return true;
        if (node.getAttribute("aria-disabled") === "true") return true;
      }
      return false;
    };
    const describe = (c: RGBA) =>
      `rgb(${Math.round(c.r)}, ${Math.round(c.g)}, ${Math.round(c.b)})`;

    const problems: ContrastProblem[] = [];
    const seen = new Set<Element>();
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
    );
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = node.textContent?.trim();
      const element = node.parentElement;
      if (!text || !element || seen.has(element)) continue;
      seen.add(element);
      if (element.closest("option, select, script, style, title")) continue;
      const rects = element.getClientRects();
      if (!rects.length || exempt(element)) continue;
      const style = getComputedStyle(element);
      const svg = element instanceof SVGElement;
      const raw = parse(svg ? style.fill : style.color);
      if (!raw) continue;
      const bg = background(element);
      const fg = raw.a < 1 ? over(raw, bg) : raw;
      const size = parseFloat(style.fontSize);
      const bold = Number(style.fontWeight) >= 700;
      const large = size >= 24 || (size >= 18.66 && bold);
      const required = large ? 3 : 4.5;
      const value = ratio(fg, bg);
      if (value + 0.005 < required)
        problems.push({
          text: text.slice(0, 60),
          ratio: Math.round(value * 100) / 100,
          required,
          color: describe(fg),
          background: describe(bg),
        });
    }
    return problems;
  });
}
