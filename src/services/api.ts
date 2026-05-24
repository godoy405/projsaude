const DEFAULT_API_BASE_URL = "https://projsaude.vercel.app/";
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? DEFAULT_API_BASE_URL;
const TOKEN_STORAGE_KEY = "projsaude_auth_token";
const ROLE_STORAGE_KEY = "projsaude_auth_role";

type ApiResult<T> = {
  ok: boolean;
  message: string;
  data?: T;
};

async function request<T>(path: string, options: RequestInit = {}): Promise<ApiResult<T>> {
  function swapHost(baseUrl: string) {
    if (baseUrl.includes("://localhost:")) {
      return baseUrl.replace("://localhost:", "://127.0.0.1:");
    }
    if (baseUrl.includes("://127.0.0.1:")) {
      return baseUrl.replace("://127.0.0.1:", "://localhost:");
    }
    return baseUrl;
  }

  async function requestWithBase(baseUrl: string) {
    const token = getAuthToken();
    const response = await fetch(`${baseUrl}${path}`, {
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(options.headers ?? {}),
      },
      ...options,
    });

    const json = (await response.json()) as { ok: boolean; message: string; data?: T; error?: string };
    const details = !response.ok && json.error ? ` (${json.error})` : "";
    return { ok: response.ok && json.ok, message: `${json.message}${details}`, data: json.data };
  }

  try {
    return await requestWithBase(API_BASE_URL);
  } catch (error) {
    const fallbackUrl = swapHost(API_BASE_URL);
    if (fallbackUrl !== API_BASE_URL) {
      try {
        return await requestWithBase(fallbackUrl);
      } catch {
        // mantém mensagem padrão abaixo
      }
    }

    const baseUrl = API_BASE_URL.replace(/\/$/, "");
    return {
      ok: false,
      message:
        `Falha de conexão com a API. Inicie o projeto com "npm run dev" e confirme acesso em ${baseUrl}.`,
    };
  }
}

export async function registerUser(payload: { name: string; email: string; password: string }) {
  return request<never>("/auth/register", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function loginUser(payload: { email: string; password: string }) {
  return request<{ token: string; user: { id: number; name: string; email: string; isAdmin: boolean } }>("/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function loginWithGoogle(credential: string) {
  return request<{ token: string; user: { id: number; name: string; email: string; isAdmin: boolean } }>(
    "/auth/social/google",
    {
      method: "POST",
      body: JSON.stringify({ credential }),
    },
  );
}

export async function loginWithApple(payload: { identityToken: string; fullName?: string }) {
  return request<{ token: string; user: { id: number; name: string; email: string; isAdmin: boolean } }>(
    "/auth/social/apple",
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
  );
}

export async function loginAdmin(payload: { email: string; password: string }) {
  return request<{ token: string; user: { id: number; name: string; email: string; isAdmin: true } }>(
    "/auth/admin/login",
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
  );
}

export async function registerAdmin(payload: { name: string; email: string; password: string }) {
  return request<never>("/auth/admin/register", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getCurrentUser() {
  return request<{ id: number; name: string; email: string; isAdmin?: boolean }>("/auth/me", {
    method: "GET",
  });
}

export type ChatApiMessage = {
  id: number;
  sender: "user" | "bot" | "system";
  kind: "text" | "audio" | "file";
  content: string;
  time: string;
};

export async function getChatMessages() {
  return request<ChatApiMessage[]>("/chat/messages", {
    method: "GET",
  });
}

export async function sendChatMessage(payload: {
  sender: ChatApiMessage["sender"];
  kind: ChatApiMessage["kind"];
  content: string;
}) {
  return request<ChatApiMessage>("/chat/messages", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export type AppointmentApiItem = {
  id: number;
  date: string;
  time: string;
  doctor: string;
  specialty: string;
  type: "consulta" | "retorno" | "exame";
  status: "agendada" | "confirmada" | "pendente";
};

export async function getAppointments() {
  return request<AppointmentApiItem[]>("/appointments", { method: "GET" });
}

export async function createAppointment(payload: Omit<AppointmentApiItem, "id">) {
  return request<AppointmentApiItem>("/appointments", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateAppointment(id: number, payload: Omit<AppointmentApiItem, "id">) {
  return request<AppointmentApiItem>(`/appointments/${id}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export async function deleteAppointment(id: number) {
  return request<never>(`/appointments/${id}`, {
    method: "DELETE",
  });
}

export type ReminderApiItem = {
  id: number;
  title: string;
  message: string;
  date: string;
  category: "medicamento" | "especial";
  endDate?: string | null;
};

export async function getReminders() {
  return request<ReminderApiItem[]>("/reminders", { method: "GET" });
}

export async function createReminder(payload: Omit<ReminderApiItem, "id">) {
  return request<ReminderApiItem>("/reminders", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateReminder(id: number, payload: Omit<ReminderApiItem, "id">) {
  return request<ReminderApiItem>(`/reminders/${id}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export async function deleteReminder(id: number) {
  return request<never>(`/reminders/${id}`, {
    method: "DELETE",
  });
}

export async function createPrescriptionRequest(payload: { medicine: string; details: string }) {
  return request<never>("/prescription-requests", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export type AdminUserItem = {
  id: number;
  name: string;
  email: string;
  createdAt: string;
};

export type AdminAppointmentItem = {
  id: number;
  userId: number;
  userName: string;
  userEmail: string;
  date: string;
  time: string;
  doctor: string;
  specialty: string;
  type: "consulta" | "retorno" | "exame";
  status: "agendada" | "confirmada" | "pendente";
};

export type AdminReminderItem = {
  id: number;
  userId: number;
  userName: string;
  userEmail: string;
  title: string;
  message: string;
  date: string;
  category: "medicamento" | "especial";
  endDate?: string | null;
};

export type AdminChatItem = {
  id: number;
  userId: number;
  userName: string;
  userEmail: string;
  sender: "user" | "bot" | "system";
  kind: "text" | "audio" | "file";
  content: string;
  createdAt: string;
};

export type AdminPrescriptionItem = {
  id: number;
  userId: number;
  userName: string;
  userEmail: string;
  medicine: string;
  details?: string | null;
  status: "pendente" | "atendida";
  createdAt: string;
};

export type AdminOverview = {
  users: AdminUserItem[];
  appointments: AdminAppointmentItem[];
  reminders: AdminReminderItem[];
  chatMessages: AdminChatItem[];
  prescriptionRequests: AdminPrescriptionItem[];
};

export async function getAdminOverview() {
  return request<AdminOverview>("/admin/overview", { method: "GET" });
}

export async function deleteAdminUser(id: number) {
  return request<never>(`/admin/users/${id}`, { method: "DELETE" });
}

export async function deleteAdminAppointment(id: number) {
  return request<never>(`/admin/appointments/${id}`, { method: "DELETE" });
}

export async function deleteAdminReminder(id: number) {
  return request<never>(`/admin/reminders/${id}`, { method: "DELETE" });
}

export async function deleteAdminChatMessage(id: number) {
  return request<never>(`/admin/chat-messages/${id}`, { method: "DELETE" });
}

export async function updateAdminPrescriptionStatus(id: number, status: "pendente" | "atendida") {
  return request<never>(`/admin/prescription-requests/${id}/status`, {
    method: "PUT",
    body: JSON.stringify({ status }),
  });
}

export function saveAuthToken(token: string, isAdmin = false) {
  localStorage.setItem(TOKEN_STORAGE_KEY, token);
  localStorage.setItem(ROLE_STORAGE_KEY, isAdmin ? "admin" : "patient");
}

export function getAuthToken() {
  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function clearAuthToken() {
  localStorage.removeItem(TOKEN_STORAGE_KEY);
  localStorage.removeItem(ROLE_STORAGE_KEY);
}

export function isAdminSession() {
  return localStorage.getItem(ROLE_STORAGE_KEY) === "admin";
}
