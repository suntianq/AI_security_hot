// Event detail page — header, summary, evidence timeline.

import { initApp } from "../bootstrap";
import { getEvent } from "../api/endpoints";
import {
  eventHeaderHtml,
  eventSummaryHtml,
  eventTimelineHtml,
} from "../components/event/EventView";
import { errorStateHtml, skeletonFeedHtml } from "../components/common/States";
import { TECH_LABELS } from "../lib/labels";

const content = initApp({ activeNav: "event", variant: "reading" });
const id = new URLSearchParams(location.search).get("id");
if (!id) {
  content.innerHTML = errorStateHtml("缺少 id 参数", () => {
    location.href = "/";
  });
} else {
  void load(id);
}

async function load(eventId: string): Promise<void> {
  content.innerHTML = skeletonFeedHtml();
  try {
    const event = await getEvent(eventId);
    content.innerHTML = `
      ${eventHeaderHtml(event, TECH_LABELS)}
      ${eventSummaryHtml(event)}
      <div class="mt-lg">${eventTimelineHtml(event)}</div>
    `;
  } catch (e) {
    content.innerHTML = errorStateHtml(
      e instanceof Error ? e.message : String(e),
      () => void load(eventId),
    );
  }
}
