// Heat score display — prominent number, restrained meter. Levels:
// 90+ 极热 / 70-89 高热 / 50-69 热点 / <50 一般.

export type HeatLevel = "lvl-1" | "lvl-2" | "lvl-3" | "lvl-4";

export function heatLevel(score: number): HeatLevel {
  if (score >= 90) return "lvl-1";
  if (score >= 70) return "lvl-2";
  if (score >= 50) return "lvl-3";
  return "lvl-4";
}

export function heatScoreHtml(score: number): string {
  const level = heatLevel(score);
  const width = Math.max(4, Math.min(100, score));
  return `
    <span class="heat-score">
      <span class="heat-num ${level}">${score}</span>
      <span class="heat-bar"><i class="${level}" style="width:${width}%"></i></span>
    </span>`;
}
