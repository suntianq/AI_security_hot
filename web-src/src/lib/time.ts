// Time helpers. All date grouping is done in Asia/Shanghai (UTC+8, no DST).

const HOURS_MS = 8 * 3600 * 1000;
const WEEKDAYS = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"];

function parse(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** YYYY-MM-DD in Asia/Shanghai for an ISO timestamp. */
export function shanghaiDateKey(iso: string | null | undefined): string {
  const d = parse(iso);
  if (!d) return "";
  const shifted = new Date(d.getTime() + HOURS_MS);
  return shifted.toISOString().slice(0, 10);
}

/** HH:MM (Shanghai) for an ISO timestamp. */
export function fmtHHMM(iso: string | null | undefined): string {
  const d = parse(iso);
  if (!d) return "";
  const shifted = new Date(d.getTime() + HOURS_MS);
  return shifted.toISOString().slice(11, 16);
}

/** "2026-08-07 14:32" (Shanghai) for an ISO timestamp. */
export function fmtDateTime(iso: string | null | undefined): string {
  const d = parse(iso);
  if (!d) return "";
  const shifted = new Date(d.getTime() + HOURS_MS);
  return shifted.toISOString().slice(0, 16).replace("T", " ");
}

/** Today's YYYY-MM-DD in Asia/Shanghai. */
export function todayShanghaiKey(): string {
  return shanghaiDateKey(new Date().toISOString());
}

/** 周五-style weekday for a YYYY-MM-DD date key. */
export function weekdayCn(dateKey: string): string {
  // Interpret the key as a Shanghai wall-clock date (midday avoids DST edges).
  const d = new Date(`${dateKey}T12:00:00`);
  return WEEKDAYS[d.getDay()];
}

/** "今天"/"昨天"/"前天" relative to today's Shanghai date, else the date key. */
export function relativeDayLabel(dateKey: string): string {
  const today = todayShanghaiKey();
  if (dateKey === today) return "今天";
  const diff = dayDiff(today, dateKey);
  if (diff === 1) return "昨天";
  if (diff === 2) return "前天";
  return dateKey;
}

function dayDiff(a: string, b: string): number {
  const da = new Date(`${a}T12:00:00Z`).getTime();
  const db = new Date(`${b}T12:00:00Z`).getTime();
  return Math.round((da - db) / 86400000);
}

/** Age threshold for "24h / 3d / 7d" range filters, in minutes. */
export function rangeCutoff(range: "today" | "24h" | "3d" | "7d"): string {
  const now = Date.now();
  const ms =
    range === "today"
      ? 0 // today: filter by Shanghai date key instead
      : range === "24h"
        ? 24 * 3600 * 1000
        : range === "3d"
          ? 3 * 24 * 3600 * 1000
          : 7 * 24 * 3600 * 1000;
  if (range === "today") return new Date(now - now % 86400000 - 8 * 3600 * 1000).toISOString();
  return new Date(now - ms).toISOString();
}
