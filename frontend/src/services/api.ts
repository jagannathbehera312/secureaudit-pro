import axios from "axios";

const API_BASE_URL = "/api";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor to attach JWT
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor for automatic refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      const refreshToken = localStorage.getItem("refresh_token");
      if (refreshToken) {
        try {
          const res = await axios.post(`${API_BASE_URL}/auth/refresh/`, { refresh: refreshToken });
          const newAccess = res.data.access;
          localStorage.setItem("access_token", newAccess);
          originalRequest.headers.Authorization = `Bearer ${newAccess}`;
          return apiClient(originalRequest);
        } catch (refreshErr) {
          localStorage.removeItem("access_token");
          localStorage.removeItem("refresh_token");
          localStorage.removeItem("user");
          window.location.href = "/login";
        }
      }
    }
    return Promise.reject(error);
  }
);

// --- APIs ---

export const authApi = {
  login: (data: any) => apiClient.post("/auth/login/", data),
  register: (data: any) => apiClient.post("/auth/register/", data),
  getProfile: () => apiClient.get("/auth/profile/"),
  updateProfile: (data: any) => apiClient.put("/auth/profile/", data),
  changePassword: (data: any) => apiClient.post("/auth/change-password/", data),
  setup2FA: () => apiClient.post("/auth/2fa/setup/"),
  verify2FA: (code: string) => apiClient.post("/auth/2fa/verify/", { code }),
  listUsers: () => apiClient.get("/auth/users/"),
};

export const organizationsApi = {
  list: () => apiClient.get("/organizations/"),
  get: (id: string) => apiClient.get(`/organizations/${id}/`),
  create: (data: any) => apiClient.post("/organizations/", data),
};

export const websitesApi = {
  list: () => apiClient.get("/websites/"),
  get: (id: string) => apiClient.get(`/websites/${id}/`),
  create: (data: any) => apiClient.post("/websites/", data),
  update: (id: string, data: any) => apiClient.put(`/websites/${id}/`, data),
  delete: (id: string) => apiClient.delete(`/websites/${id}/`),
  verify: (id: string, method: string) => apiClient.post(`/websites/${id}/verify/`, { method }),
};

export const scansApi = {
  list: (params?: any) => apiClient.get("/scans/", { params }),
  get: (id: string) => apiClient.get(`/scans/${id}/`),
  create: (data: any) => apiClient.post("/scans/", data),
  stop: (id: string) => apiClient.post(`/scans/${id}/stop/`),
  retry: (id: string) => apiClient.post(`/scans/${id}/retry/`),
  getEvents: (id: string) => apiClient.get(`/scans/${id}/events/`),
  getResults: (id: string) => apiClient.get(`/scans/${id}/results/`),
  compare: (scan_id_a: string, scan_id_b: string) => apiClient.post("/scans/compare/", { scan_id_a, scan_id_b }),
};

export const vulnerabilitiesApi = {
  list: (params?: any) => apiClient.get("/vulnerabilities/", { params }),
  get: (id: string) => apiClient.get(`/vulnerabilities/${id}/`),
  update: (id: string, data: any) => apiClient.patch(`/vulnerabilities/${id}/`, data),
  addComment: (id: string, comment: string) => apiClient.post(`/vulnerabilities/${id}/comments/`, { comment }),
  retest: (id: string) => apiClient.post(`/vulnerabilities/${id}/retest/`),
};

export const remediationApi = {
  list: (params?: any) => apiClient.get("/remediation/", { params }),
  get: (id: string) => apiClient.get(`/remediation/${id}/`),
  create: (data: any) => apiClient.post("/remediation/", data),
  update: (id: string, data: any) => apiClient.patch(`/remediation/${id}/`, data),
};

export const reportsApi = {
  list: () => apiClient.get("/reports/"),
  generate: (data: any) => apiClient.post("/reports/", data),
  getDownloadUrl: (id: string, format: string = "pdf") => {
    const token = localStorage.getItem("accessToken");
    const q = token ? `?token=${encodeURIComponent(token)}&format=${format}` : `?format=${format}`;
    return `${API_BASE_URL}/reports/${id}/download/${q}`;
  },
  downloadBlob: (id: string, format: string = "pdf") =>
    apiClient.get(`/reports/${id}/download/?format=${format}`, { responseType: "blob" }),
};

export const adminApi = {
  getStats: () => apiClient.get("/admin/dashboard/"),
  getHealth: () => apiClient.get("/admin/system-health/"),
  getAuditLogs: () => apiClient.get("/admin/audit-logs/"),
  resetDemoData: () => apiClient.post("/admin/reset-demo/"),
};

export const notificationsApi = {
  list: () => apiClient.get("/notifications/"),
  markRead: (id: string) => apiClient.post(`/notifications/${id}/read/`),
};

export const monitoringApi = {
  list: () => apiClient.get("/monitoring/"),
  create: (data: any) => apiClient.post("/monitoring/", data),
  get: (id: string) => apiClient.get(`/monitoring/${id}/`),
  checkNow: (id: string) => apiClient.post(`/monitoring/${id}/check/`),
  delete: (id: string) => apiClient.delete(`/monitoring/${id}/`),
  getEvents: (params?: any) => apiClient.get("/monitoring/events/", { params }),
  resolveEvent: (id: string, notes?: string) => apiClient.post(`/monitoring/events/${id}/resolve/`, { resolution_notes: notes }),
};
