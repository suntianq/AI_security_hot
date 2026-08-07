// Typed contracts mirroring the backend API responses. Never invent fields.

export interface Hotspot {
  id: number;
  title: string;
  summary: string;
  topic: string | null;
  score: number;
  source_count: number;
  last: string | null;
}

export interface ModuleItem {
  id?: number; // present on /api/feed and /api/search
  document_id: number;
  title: string;
  summary: string;
  url: string;
  source: string;
  source_name: string;
  tech: string[];
  etype: string | null;
  fetched: string;
  published_at?: string | null; // present on /api/feed and /api/search
  module?: string; // present on /api/feed and /api/search
}

export interface Module {
  id: string;
  label: string;
  items: ModuleItem[];
}

export interface Labels {
  source: Record<string, string>;
  tech: Record<string, string>;
}

export interface Overview {
  generated_at: string;
  date: string;
  weekday: string;
  hotspots: Hotspot[];
  modules: Module[];
  url_sources: Record<string, string[]>;
  labels: Labels;
}

export interface FeedResponse {
  items: ModuleItem[];
  next_before: string | null;
  labels: Labels;
}

export interface SearchResponse {
  total: number;
  items: ModuleItem[];
  page: number;
  limit: number;
  labels: Labels;
}

export interface Evidence {
  document_id: number;
  title: string;
  url: string;
  source_name: string;
  published_at: string | null;
  stance: string;
  evidence_level: string | null;
  relation_reason: string | null;
}

export interface EventDetail {
  id: number;
  title: string;
  summary: string | null;
  topic: string | null;
  category: string | null;
  event_type: string | null;
  score: number | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  evidence: Evidence[];
}

export interface DocumentDetail {
  id: number;
  title: string;
  body: string | null;
  url: string;
  source: string;
  source_name: string;
  published_at: string | null;
  tech_directions: string[];
  company_models: string[];
  event_type: string | null;
}

export interface FeedQuery {
  limit?: number;
  before?: string;
  since?: string;
  module?: string;
  tech_direction?: string;
  source?: string;
}

export interface SearchQuery {
  q: string;
  module?: string;
  tech_direction?: string;
  source?: string;
  page?: number;
  limit?: number;
}
