import type {
  AnalysisResult,
  DashboardStats,
  EmailAnalysisRequest,
  HealthStatus,
  ModelStatus,
  ScanPage,
  TrendResponse,
  UrlAnalysisRequest,
  ValidationIssue,
} from "../types/api";

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly issues: ValidationIssue[];

  constructor(message: string, status: number, issues: ValidationIssue[] = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.issues = issues;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      ...init,
    });
  } catch {
    throw new ApiError(
      "Cannot reach the PhishGuard API. Is the backend running on port 8000?",
      0,
    );
  }

  if (!response.ok) {
    let message = `Request failed with status ${response.status}.`;
    let issues: ValidationIssue[] = [];
    try {
      const body = (await response.json()) as {
        detail?: string;
        errors?: ValidationIssue[];
      };
      if (typeof body.detail === "string") message = body.detail;
      if (Array.isArray(body.errors)) issues = body.errors;
    } catch {
      // Keep the generic message when the error body is not JSON.
    }
    throw new ApiError(message, response.status, issues);
  }

  return (await response.json()) as T;
}

function query(params: Record<string, string | number | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export const api = {
  health: () => request<HealthStatus>("/health"),
  modelStatus: () => request<ModelStatus>("/models/status"),

  analyzeEmail: (payload: EmailAnalysisRequest) =>
    request<AnalysisResult>("/analyze/email", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  analyzeUrl: (payload: UrlAnalysisRequest) =>
    request<AnalysisResult>("/analyze/url", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listScans: (params: {
    page?: number;
    page_size?: number;
    search?: string;
    classification?: string;
    scan_type?: string;
  }) => request<ScanPage>(`/scans${query(params)}`),

  getScan: (id: number) => request<AnalysisResult>(`/scans/${id}`),

  dashboardStats: () => request<DashboardStats>("/dashboard/stats"),

  dashboardTrend: (days = 14) =>
    request<TrendResponse>(`/dashboard/trend${query({ days })}`),
};
