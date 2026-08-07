// One typed function per public API route.

import { api } from "./client";
import type {
  DocumentDetail,
  EventDetail,
  FeedQuery,
  FeedResponse,
  Overview,
  SearchQuery,
  SearchResponse,
} from "./types";

export const getOverview = (p?: { date?: string }): Promise<Overview> =>
  api<Overview>("/api/overview", p);

export const getArchives = (): Promise<{ dates: string[] }> =>
  api<{ dates: string[] }>("/api/daily/archives");

export const getArchive = (date: string): Promise<Overview> =>
  api<Overview>(`/api/daily/archives/${date}`);

export const getEvent = (id: number | string): Promise<EventDetail> =>
  api<EventDetail>(`/api/event/${id}`);

export const getDocument = (id: number | string): Promise<DocumentDetail> =>
  api<DocumentDetail>(`/api/document/${id}`);

export const getFeed = (p: FeedQuery): Promise<FeedResponse> =>
  api<FeedResponse>("/api/feed", p);

export const searchAll = (p: SearchQuery): Promise<SearchResponse> =>
  api<SearchResponse>("/api/search", p);
