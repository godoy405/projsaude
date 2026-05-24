import bcrypt from "bcryptjs";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import appleSigninAuth from "apple-signin-auth";
import { initDatabase, query, testConnection } from "./db.js";

const app = express();
const port = Number(process.env.PORT ?? 3333);
const jwtSecret = process.env.JWT_SECRET ?? "projsaude_jwt_dev_secret";
const googleClientId = String(process.env.GOOGLE_CLIENT_ID ?? "").trim();
const appleClientId = String(process.env.APPLE_CLIENT_ID ?? "").trim();
const adminEmails = String(process.env.ADMIN_EMAILS ?? "")
  .split(",")
  .map((email) => email.trim().toLowerCase())
  .filter(Boolean);
const googleOAuthClient = googleClientId ? new OAuth2Client(googleClientId) : null;

app.use(cors())
app.use(express.json());

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function isStrongPassword(password) {
  const hasMinLength = password.length >= 8;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  return hasMinLength && hasUpper && hasLower && hasDigit && hasSpecial;
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";

  if (!token) {
    return res.status(401).json({ ok: false, message: "Token ausente." });
  }

  try {
    const payload = jwt.verify(token, jwtSecret);
    req.authUser = payload;
    return next();
  } catch {
    return res.status(401).json({ ok: false, message: "Token inválido ou expirado." });
  }
}

function isAdminUser(authUser) {
  if (authUser?.role === "admin") {
    return true;
  }
  if (Number(authUser?.is_admin ?? 0) === 1) {
    return true;
  }
  const normalizedEmail = String(authUser?.email ?? "").trim().toLowerCase();
  if (!normalizedEmail) {
    return false;
  }
  return adminEmails.includes(normalizedEmail);
}

function adminMiddleware(req, res, next) {
  if (!isAdminUser(req.authUser)) {
    return res.status(403).json({ ok: false, message: "Acesso restrito ao painel administrativo." });
  }
  return next();
}

function issueAuthToken(user) {
  const isAdmin = isAdminUser(user);
  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: isAdmin ? "admin" : "patient",
      is_admin: Number(user.is_admin ?? 0),
    },
    jwtSecret,
    { expiresIn: "12h" },
  );
  return { token, isAdmin };
}

async function createUserFromSocial({ name, email }) {
  const normalizedName = String(name ?? "").trim() || "Usuário";
  const normalizedEmail = String(email ?? "").trim().toLowerCase();
  const socialPasswordHash = await bcrypt.hash(
    `social:${normalizedEmail}:${Date.now()}:${Math.random().toString(36).slice(2)}`,
    10,
  );

  await query("INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, 0)", [
    normalizedName,
    normalizedEmail,
    socialPasswordHash,
  ]);

  const users = await query("SELECT id, name, email, is_admin FROM users WHERE email = ? LIMIT 1", [normalizedEmail]);
  return Array.isArray(users) && users.length ? users[0] : null;
}

async function findUserByEmail(email) {
  const users = await query("SELECT id, name, email, is_admin FROM users WHERE email = ? LIMIT 1", [
    String(email ?? "").trim().toLowerCase(),
  ]);
  return Array.isArray(users) && users.length ? users[0] : null;
}

async function findUserBySocialAccount(provider, providerUserId) {
  const rows = await query(
    `
      SELECT u.id, u.name, u.email, u.is_admin
      FROM social_accounts s
      INNER JOIN users u ON u.id = s.user_id
      WHERE s.provider = ? AND s.provider_user_id = ?
      LIMIT 1
    `,
    [provider, providerUserId],
  );
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

async function upsertSocialAccount({ userId, provider, providerUserId, providerEmail }) {
  await query(
    `
      INSERT INTO social_accounts (user_id, provider, provider_user_id, provider_email)
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), provider_email = VALUES(provider_email)
    `,
    [userId, provider, providerUserId, providerEmail || null],
  );
}

app.get("/api/health", async (_req, res) => {
  try {
    await testConnection();
    res.json({ ok: true, message: "API conectada ao MySQL com sucesso." });
  } catch (error) {
    res.status(500).json({ ok: false, message: "Falha ao conectar no MySQL.", error: String(error) });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body ?? {};
    const normalizedEmail = String(email ?? "").trim().toLowerCase();
    const normalizedName = String(name ?? "").trim();

    if (!normalizedName || !normalizedEmail || !password) {
      return res.status(400).json({ ok: false, message: "Preencha nome, email e senha." });
    }

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ ok: false, message: "Formato de e-mail inválido." });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        ok: false,
        message: "A senha deve ter 8+ caracteres, maiúscula, minúscula, número e símbolo.",
      });
    }

    const existing = await query("SELECT id FROM users WHERE email = ? LIMIT 1", [normalizedEmail]);
    if (Array.isArray(existing) && existing.length > 0) {
      return res.status(409).json({ ok: false, message: "Este e-mail já está cadastrado." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await query("INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, 0)", [
      normalizedName,
      normalizedEmail,
      passwordHash,
    ]);

    return res.status(201).json({ ok: true, message: "Cadastro realizado com sucesso." });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao cadastrar usuário.", error: String(error) });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    const normalizedEmail = String(email ?? "").trim().toLowerCase();

    if (!normalizedEmail || !password) {
      return res.status(400).json({ ok: false, message: "Informe email e senha." });
    }

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ ok: false, message: "Formato de e-mail inválido." });
    }

    const users = await query("SELECT id, name, email, password_hash, is_admin FROM users WHERE email = ? LIMIT 1", [
      normalizedEmail,
    ]);
    if (!Array.isArray(users) || users.length === 0) {
      return res.status(401).json({ ok: false, message: "Credenciais inválidas." });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ ok: false, message: "Credenciais inválidas." });
    }

    const { token, isAdmin } = issueAuthToken(user);

    return res.json({
      ok: true,
      message: "Login efetuado com sucesso.",
      data: {
        token,
        user: { id: user.id, name: user.name, email: user.email, isAdmin },
      },
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao realizar login.", error: String(error) });
  }
});

app.get("/", async (_, res) => {
    return res.status(200).json("API Rodando");
})

app.post("/api/auth/social/google", async (req, res) => {
  try {
    const credential = String(req.body?.credential ?? "").trim();
    if (!credential) {
      return res.status(400).json({ ok: false, message: "Token do Google não informado." });
    }

    if (!googleOAuthClient || !googleClientId) {
      return res.status(500).json({ ok: false, message: "Login Google não configurado no servidor." });
    }

    const ticket = await googleOAuthClient.verifyIdToken({
      idToken: credential,
      audience: googleClientId,
    });
    const payload = ticket.getPayload();
    const email = String(payload?.email ?? "").trim().toLowerCase();
    const providerUserId = String(payload?.sub ?? "").trim();
    const name = String(payload?.name ?? "").trim() || "Usuário Google";

    if (!providerUserId || !email || payload?.email_verified !== true) {
      return res.status(400).json({ ok: false, message: "Conta Google inválida para autenticação." });
    }

    let user = await findUserBySocialAccount("google", providerUserId);
    if (!user) {
      user = await findUserByEmail(email);
    }
    if (!user) {
      user = await createUserFromSocial({ name, email });
    }
    if (!user) {
      return res.status(500).json({ ok: false, message: "Não foi possível criar usuário via Google." });
    }

    await upsertSocialAccount({
      userId: user.id,
      provider: "google",
      providerUserId,
      providerEmail: email,
    });

    const { token, isAdmin } = issueAuthToken(user);
    return res.json({
      ok: true,
      message: "Login com Google efetuado com sucesso.",
      data: { token, user: { id: user.id, name: user.name, email: user.email, isAdmin } },
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao autenticar com Google.", error: String(error) });
  }
});

app.post("/api/auth/social/apple", async (req, res) => {
  try {
    const identityToken = String(req.body?.identityToken ?? "").trim();
    const fullName = String(req.body?.fullName ?? "").trim();
    if (!identityToken) {
      return res.status(400).json({ ok: false, message: "Token da Apple não informado." });
    }
    if (!appleClientId) {
      return res.status(500).json({ ok: false, message: "Login Apple não configurado no servidor." });
    }

    const claims = await appleSigninAuth.verifyIdToken(identityToken, {
      audience: appleClientId,
      issuer: "https://appleid.apple.com",
      ignoreExpiration: false,
    });

    const providerUserId = String(claims?.sub ?? "").trim();
    const email = String(claims?.email ?? "").trim().toLowerCase();
    if (!providerUserId) {
      return res.status(400).json({ ok: false, message: "Conta Apple inválida para autenticação." });
    }

    let user = await findUserBySocialAccount("apple", providerUserId);
    if (!user && email) {
      user = await findUserByEmail(email);
    }
    if (!user && email) {
      user = await createUserFromSocial({ name: fullName || "Usuário Apple", email });
    }
    if (!user) {
      return res.status(400).json({
        ok: false,
        message: "Não foi possível identificar e-mail da conta Apple. Tente novamente e permita compartilhar e-mail.",
      });
    }

    await upsertSocialAccount({
      userId: user.id,
      provider: "apple",
      providerUserId,
      providerEmail: email || user.email,
    });

    const { token, isAdmin } = issueAuthToken(user);
    return res.json({
      ok: true,
      message: "Login com Apple efetuado com sucesso.",
      data: { token, user: { id: user.id, name: user.name, email: user.email, isAdmin } },
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao autenticar com Apple.", error: String(error) });
  }
});

app.post("/api/auth/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    const normalizedEmail = String(email ?? "").trim().toLowerCase();

    if (!normalizedEmail || !password) {
      return res.status(400).json({ ok: false, message: "Informe email e senha." });
    }

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ ok: false, message: "Formato de e-mail inválido." });
    }

    const users = await query("SELECT id, name, email, password_hash, is_admin FROM users WHERE email = ? LIMIT 1", [
      normalizedEmail,
    ]);
    if (!Array.isArray(users) || users.length === 0) {
      return res.status(404).json({ ok: false, message: "Usuário não cadastrado." });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ ok: false, message: "Senha inválida." });
    }

    if (!isAdminUser(user)) {
      return res.status(403).json({
        ok: false,
        message: "Usuário sem permissão de administrador.",
      });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: "admin", is_admin: 1 }, jwtSecret, {
      expiresIn: "12h",
    });

    return res.json({
      ok: true,
      message: "Login administrativo efetuado com sucesso.",
      data: {
        token,
        user: { id: user.id, name: user.name, email: user.email, isAdmin: true },
      },
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao realizar login administrativo.", error: String(error) });
  }
});

app.post("/api/auth/admin/register", async (req, res) => {
  try {
    const { name, email, password } = req.body ?? {};
    const normalizedName = String(name ?? "").trim();
    const normalizedEmail = String(email ?? "").trim().toLowerCase();

    if (!normalizedName || !normalizedEmail || !password) {
      return res.status(400).json({ ok: false, message: "Preencha nome, email e senha." });
    }

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ ok: false, message: "Formato de e-mail inválido." });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        ok: false,
        message: "A senha deve ter 8+ caracteres, maiúscula, minúscula, número e símbolo.",
      });
    }

    const existing = await query("SELECT id FROM users WHERE email = ? LIMIT 1", [normalizedEmail]);
    if (Array.isArray(existing) && existing.length > 0) {
      return res.status(409).json({ ok: false, message: "Este e-mail já está cadastrado." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await query("INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, 1)", [
      normalizedName,
      normalizedEmail,
      passwordHash,
    ]);

    return res.status(201).json({ ok: true, message: "Administrador cadastrado com sucesso." });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao cadastrar administrador.", error: String(error) });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const users = await query("SELECT id, name, email, is_admin FROM users WHERE id = ? LIMIT 1", [req.authUser.id]);
    if (!Array.isArray(users) || users.length === 0) {
      return res.status(404).json({ ok: false, message: "Usuário não encontrado." });
    }
    return res.json({
      ok: true,
      message: "Usuario autenticado.",
      data: { ...users[0], isAdmin: isAdminUser(users[0]) },
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao buscar usuário.", error: String(error) });
  }
});

app.get("/api/admin/overview", authMiddleware, adminMiddleware, async (_req, res) => {
  try {
    const [users, appointments, reminders, chatMessages, prescriptionRequests] = await Promise.all([
      query(
        `
        SELECT id, name, email, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS createdAt
        FROM users
        ORDER BY id DESC
        LIMIT 500
      `,
      ),
      query(
        `
        SELECT
          a.id,
          a.user_id AS userId,
          u.name AS userName,
          u.email AS userEmail,
          DATE_FORMAT(a.appointment_date, '%Y-%m-%d') AS date,
          DATE_FORMAT(a.appointment_time, '%H:%i') AS time,
          a.doctor,
          a.specialty,
          a.type,
          a.status
        FROM appointments a
        INNER JOIN users u ON u.id = a.user_id
        ORDER BY a.id DESC
        LIMIT 1000
      `,
      ),
      query(
        `
        SELECT
          r.id,
          r.user_id AS userId,
          u.name AS userName,
          u.email AS userEmail,
          r.title,
          r.message,
          DATE_FORMAT(r.reminder_date, '%Y-%m-%d') AS date,
          r.category,
          IF(r.end_date IS NULL, NULL, DATE_FORMAT(r.end_date, '%Y-%m-%d')) AS endDate
        FROM reminders r
        INNER JOIN users u ON u.id = r.user_id
        ORDER BY r.id DESC
        LIMIT 1000
      `,
      ),
      query(
        `
        SELECT
          c.id,
          c.user_id AS userId,
          u.name AS userName,
          u.email AS userEmail,
          c.sender,
          c.kind,
          c.content,
          DATE_FORMAT(c.created_at, '%Y-%m-%d %H:%i') AS createdAt
        FROM chat_messages c
        INNER JOIN users u ON u.id = c.user_id
        ORDER BY c.id DESC
        LIMIT 1000
      `,
      ),
      query(
        `
        SELECT
          p.id,
          p.user_id AS userId,
          u.name AS userName,
          u.email AS userEmail,
          p.medicine,
          p.details,
          p.status,
          DATE_FORMAT(p.created_at, '%Y-%m-%d %H:%i') AS createdAt
        FROM prescription_requests p
        INNER JOIN users u ON u.id = p.user_id
        ORDER BY p.id DESC
        LIMIT 1000
      `,
      ),
    ]);

    return res.json({
      ok: true,
      message: "Dados administrativos carregados.",
      data: { users, appointments, reminders, chatMessages, prescriptionRequests },
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao carregar painel administrativo.", error: String(error) });
  }
});

app.delete("/api/admin/users/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    if (!userId) {
      return res.status(400).json({ ok: false, message: "ID de usuário inválido." });
    }
    if (userId === Number(req.authUser.id)) {
      return res.status(400).json({ ok: false, message: "Não é permitido excluir o próprio usuário administrador." });
    }

    const deleteResult = await query("DELETE FROM users WHERE id = ?", [userId]);
    if (!deleteResult.affectedRows) {
      return res.status(404).json({ ok: false, message: "Usuário não encontrado para exclusão." });
    }

    return res.json({ ok: true, message: "Usuário excluído com sucesso." });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao excluir usuário.", error: String(error) });
  }
});

app.delete("/api/admin/appointments/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const appointmentId = Number(req.params.id);
    if (!appointmentId) {
      return res.status(400).json({ ok: false, message: "ID da consulta inválido." });
    }

    const deleteResult = await query("DELETE FROM appointments WHERE id = ?", [appointmentId]);
    if (!deleteResult.affectedRows) {
      return res.status(404).json({ ok: false, message: "Consulta não encontrada para exclusão." });
    }

    return res.json({ ok: true, message: "Consulta excluída com sucesso." });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao excluir consulta.", error: String(error) });
  }
});

app.delete("/api/admin/reminders/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const reminderId = Number(req.params.id);
    if (!reminderId) {
      return res.status(400).json({ ok: false, message: "ID do lembrete inválido." });
    }

    const deleteResult = await query("DELETE FROM reminders WHERE id = ?", [reminderId]);
    if (!deleteResult.affectedRows) {
      return res.status(404).json({ ok: false, message: "Lembrete não encontrado para exclusão." });
    }

    return res.json({ ok: true, message: "Lembrete excluído com sucesso." });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao excluir lembrete.", error: String(error) });
  }
});

app.delete("/api/admin/chat-messages/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const messageId = Number(req.params.id);
    if (!messageId) {
      return res.status(400).json({ ok: false, message: "ID da mensagem inválido." });
    }

    const deleteResult = await query("DELETE FROM chat_messages WHERE id = ?", [messageId]);
    if (!deleteResult.affectedRows) {
      return res.status(404).json({ ok: false, message: "Mensagem não encontrada para exclusão." });
    }

    return res.json({ ok: true, message: "Mensagem excluída com sucesso." });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao excluir mensagem.", error: String(error) });
  }
});

app.put("/api/admin/prescription-requests/:id/status", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const requestId = Number(req.params.id);
    const normalizedStatus = String(req.body?.status ?? "").trim();
    const validStatus = ["pendente", "atendida"];

    if (!requestId || !validStatus.includes(normalizedStatus)) {
      return res.status(400).json({ ok: false, message: "Dados inválidos para atualizar status da receita." });
    }

    const updateResult = await query("UPDATE prescription_requests SET status = ? WHERE id = ?", [
      normalizedStatus,
      requestId,
    ]);
    if (!updateResult.affectedRows) {
      return res.status(404).json({ ok: false, message: "Solicitação de receita não encontrada." });
    }

    return res.json({ ok: true, message: "Status da solicitação atualizado com sucesso." });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao atualizar solicitação de receita.", error: String(error) });
  }
});

app.get("/api/chat/messages", authMiddleware, async (req, res) => {
  try {
    const rows = await query(
      `
      SELECT
        id,
        sender,
        kind,
        content,
        DATE_FORMAT(created_at, '%H:%i') AS time
      FROM chat_messages
      WHERE user_id = ?
      ORDER BY created_at ASC, id ASC
      LIMIT 300
    `,
      [req.authUser.id],
    );

    return res.json({
      ok: true,
      message: "Mensagens carregadas com sucesso.",
      data: rows,
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao carregar mensagens.", error: String(error) });
  }
});

app.post("/api/chat/messages", authMiddleware, async (req, res) => {
  try {
    const { sender, kind, content } = req.body ?? {};
    const normalizedSender = String(sender ?? "").trim();
    const normalizedKind = String(kind ?? "").trim();
    const normalizedContent = String(content ?? "").trim();

    if (!normalizedSender || !normalizedKind || !normalizedContent) {
      return res.status(400).json({ ok: false, message: "Informe remetente, tipo e conteúdo da mensagem." });
    }

    const validSenders = ["user", "bot", "system"];
    const validKinds = ["text", "audio", "file"];
    if (!validSenders.includes(normalizedSender) || !validKinds.includes(normalizedKind)) {
      return res.status(400).json({ ok: false, message: "Valores inválidos para remetente ou tipo." });
    }

    await query(
      "INSERT INTO chat_messages (user_id, sender, kind, content) VALUES (?, ?, ?, ?)",
      [req.authUser.id, normalizedSender, normalizedKind, normalizedContent],
    );

    const rows = await query(
      `
      SELECT
        id,
        sender,
        kind,
        content,
        DATE_FORMAT(created_at, '%H:%i') AS time
      FROM chat_messages
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT 1
    `,
      [req.authUser.id],
    );

    return res.status(201).json({
      ok: true,
      message: "Mensagem enviada com sucesso.",
      data: Array.isArray(rows) && rows.length ? rows[0] : null,
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao enviar mensagem.", error: String(error) });
  }
});

app.get("/api/appointments", authMiddleware, async (req, res) => {
  try {
    const rows = await query(
      `
      SELECT
        id,
        DATE_FORMAT(appointment_date, '%Y-%m-%d') AS date,
        DATE_FORMAT(appointment_time, '%H:%i') AS time,
        doctor,
        specialty,
        type,
        status
      FROM appointments
      WHERE user_id = ?
      ORDER BY appointment_date ASC, appointment_time ASC, id ASC
    `,
      [req.authUser.id],
    );

    return res.json({ ok: true, message: "Consultas carregadas com sucesso.", data: rows });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao carregar consultas.", error: String(error) });
  }
});

app.post("/api/appointments", authMiddleware, async (req, res) => {
  try {
    const { date, time, doctor, specialty, type, status } = req.body ?? {};
    const normalizedDate = String(date ?? "").trim();
    const normalizedTime = String(time ?? "").trim();
    const normalizedDoctor = String(doctor ?? "").trim();
    const normalizedSpecialty = String(specialty ?? "").trim();
    const normalizedType = String(type ?? "").trim();
    const normalizedStatus = String(status ?? "").trim() || "agendada";

    if (!normalizedDate || !normalizedTime || !normalizedDoctor || !normalizedSpecialty || !normalizedType) {
      return res.status(400).json({ ok: false, message: "Preencha data, hora, médico, especialidade e tipo." });
    }

    const validTypes = ["consulta", "retorno", "exame"];
    const validStatus = ["agendada", "confirmada", "pendente"];
    if (!validTypes.includes(normalizedType) || !validStatus.includes(normalizedStatus)) {
      return res.status(400).json({ ok: false, message: "Tipo ou status da consulta inválido." });
    }

    await query(
      `
      INSERT INTO appointments (user_id, appointment_date, appointment_time, doctor, specialty, type, status)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
      [
        req.authUser.id,
        normalizedDate,
        `${normalizedTime}:00`.slice(0, 8),
        normalizedDoctor,
        normalizedSpecialty,
        normalizedType,
        normalizedStatus,
      ],
    );

    const rows = await query(
      `
      SELECT
        id,
        DATE_FORMAT(appointment_date, '%Y-%m-%d') AS date,
        DATE_FORMAT(appointment_time, '%H:%i') AS time,
        doctor,
        specialty,
        type,
        status
      FROM appointments
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT 1
    `,
      [req.authUser.id],
    );

    return res.status(201).json({
      ok: true,
      message: "Consulta salva com sucesso.",
      data: Array.isArray(rows) && rows.length ? rows[0] : null,
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao salvar consulta.", error: String(error) });
  }
});

app.put("/api/appointments/:id", authMiddleware, async (req, res) => {
  try {
    const appointmentId = Number(req.params.id);
    const { date, time, doctor, specialty, type, status } = req.body ?? {};
    const normalizedDate = String(date ?? "").trim();
    const normalizedTime = String(time ?? "").trim();
    const normalizedDoctor = String(doctor ?? "").trim();
    const normalizedSpecialty = String(specialty ?? "").trim();
    const normalizedType = String(type ?? "").trim();
    const normalizedStatus = String(status ?? "").trim() || "agendada";

    if (!appointmentId || !normalizedDate || !normalizedTime || !normalizedDoctor || !normalizedSpecialty || !normalizedType) {
      return res.status(400).json({ ok: false, message: "Dados da consulta inválidos para atualização." });
    }

    const validTypes = ["consulta", "retorno", "exame"];
    const validStatus = ["agendada", "confirmada", "pendente"];
    if (!validTypes.includes(normalizedType) || !validStatus.includes(normalizedStatus)) {
      return res.status(400).json({ ok: false, message: "Tipo ou status da consulta inválido." });
    }

    const updateResult = await query(
      `
      UPDATE appointments
      SET appointment_date = ?, appointment_time = ?, doctor = ?, specialty = ?, type = ?, status = ?
      WHERE id = ? AND user_id = ?
    `,
      [
        normalizedDate,
        `${normalizedTime}:00`.slice(0, 8),
        normalizedDoctor,
        normalizedSpecialty,
        normalizedType,
        normalizedStatus,
        appointmentId,
        req.authUser.id,
      ],
    );

    if (!updateResult.affectedRows) {
      return res.status(404).json({ ok: false, message: "Consulta não encontrada para atualizar." });
    }

    const rows = await query(
      `
      SELECT
        id,
        DATE_FORMAT(appointment_date, '%Y-%m-%d') AS date,
        DATE_FORMAT(appointment_time, '%H:%i') AS time,
        doctor,
        specialty,
        type,
        status
      FROM appointments
      WHERE id = ? AND user_id = ?
      LIMIT 1
    `,
      [appointmentId, req.authUser.id],
    );

    return res.json({
      ok: true,
      message: "Consulta atualizada com sucesso.",
      data: Array.isArray(rows) && rows.length ? rows[0] : null,
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao atualizar consulta.", error: String(error) });
  }
});

app.delete("/api/appointments/:id", authMiddleware, async (req, res) => {
  try {
    const appointmentId = Number(req.params.id);
    if (!appointmentId) {
      return res.status(400).json({ ok: false, message: "ID da consulta inválido." });
    }

    const deleteResult = await query("DELETE FROM appointments WHERE id = ? AND user_id = ?", [
      appointmentId,
      req.authUser.id,
    ]);

    if (!deleteResult.affectedRows) {
      return res.status(404).json({ ok: false, message: "Consulta não encontrada para exclusão." });
    }

    return res.json({ ok: true, message: "Consulta removida com sucesso." });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao remover consulta.", error: String(error) });
  }
});

app.get("/api/reminders", authMiddleware, async (req, res) => {
  try {
    const rows = await query(
      `
      SELECT
        id,
        title,
        message,
        DATE_FORMAT(reminder_date, '%Y-%m-%d') AS date,
        category,
        IF(end_date IS NULL, NULL, DATE_FORMAT(end_date, '%Y-%m-%d')) AS endDate
      FROM reminders
      WHERE user_id = ?
      ORDER BY reminder_date DESC, id DESC
    `,
      [req.authUser.id],
    );

    return res.json({ ok: true, message: "Lembretes carregados com sucesso.", data: rows });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao carregar lembretes.", error: String(error) });
  }
});

app.post("/api/reminders", authMiddleware, async (req, res) => {
  try {
    const { title, message, date, category, endDate } = req.body ?? {};
    const normalizedTitle = String(title ?? "").trim();
    const normalizedMessage = String(message ?? "").trim();
    const normalizedDate = String(date ?? "").trim();
    const normalizedCategory = String(category ?? "").trim();
    const normalizedEndDate = String(endDate ?? "").trim();

    if (!normalizedTitle || !normalizedMessage || !normalizedDate || !normalizedCategory) {
      return res.status(400).json({ ok: false, message: "Preencha título, mensagem, data e categoria." });
    }

    const validCategories = ["medicamento", "especial"];
    if (!validCategories.includes(normalizedCategory)) {
      return res.status(400).json({ ok: false, message: "Categoria de lembrete inválida." });
    }

    await query(
      `
      INSERT INTO reminders (user_id, title, message, reminder_date, category, end_date)
      VALUES (?, ?, ?, ?, ?, ?)
    `,
      [
        req.authUser.id,
        normalizedTitle,
        normalizedMessage,
        normalizedDate,
        normalizedCategory,
        normalizedCategory === "medicamento" && normalizedEndDate ? normalizedEndDate : null,
      ],
    );

    const rows = await query(
      `
      SELECT
        id,
        title,
        message,
        DATE_FORMAT(reminder_date, '%Y-%m-%d') AS date,
        category,
        IF(end_date IS NULL, NULL, DATE_FORMAT(end_date, '%Y-%m-%d')) AS endDate
      FROM reminders
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT 1
    `,
      [req.authUser.id],
    );

    return res.status(201).json({
      ok: true,
      message: "Lembrete salvo com sucesso.",
      data: Array.isArray(rows) && rows.length ? rows[0] : null,
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao salvar lembrete.", error: String(error) });
  }
});

app.put("/api/reminders/:id", authMiddleware, async (req, res) => {
  try {
    const reminderId = Number(req.params.id);
    const { title, message, date, category, endDate } = req.body ?? {};
    const normalizedTitle = String(title ?? "").trim();
    const normalizedMessage = String(message ?? "").trim();
    const normalizedDate = String(date ?? "").trim();
    const normalizedCategory = String(category ?? "").trim();
    const normalizedEndDate = String(endDate ?? "").trim();

    if (!reminderId || !normalizedTitle || !normalizedMessage || !normalizedDate || !normalizedCategory) {
      return res.status(400).json({ ok: false, message: "Dados do lembrete inválidos para atualização." });
    }

    const validCategories = ["medicamento", "especial"];
    if (!validCategories.includes(normalizedCategory)) {
      return res.status(400).json({ ok: false, message: "Categoria de lembrete inválida." });
    }

    const updateResult = await query(
      `
      UPDATE reminders
      SET title = ?, message = ?, reminder_date = ?, category = ?, end_date = ?
      WHERE id = ? AND user_id = ?
    `,
      [
        normalizedTitle,
        normalizedMessage,
        normalizedDate,
        normalizedCategory,
        normalizedCategory === "medicamento" && normalizedEndDate ? normalizedEndDate : null,
        reminderId,
        req.authUser.id,
      ],
    );

    if (!updateResult.affectedRows) {
      return res.status(404).json({ ok: false, message: "Lembrete não encontrado para atualizar." });
    }

    const rows = await query(
      `
      SELECT
        id,
        title,
        message,
        DATE_FORMAT(reminder_date, '%Y-%m-%d') AS date,
        category,
        IF(end_date IS NULL, NULL, DATE_FORMAT(end_date, '%Y-%m-%d')) AS endDate
      FROM reminders
      WHERE id = ? AND user_id = ?
      LIMIT 1
    `,
      [reminderId, req.authUser.id],
    );

    return res.json({
      ok: true,
      message: "Lembrete atualizado com sucesso.",
      data: Array.isArray(rows) && rows.length ? rows[0] : null,
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao atualizar lembrete.", error: String(error) });
  }
});

app.delete("/api/reminders/:id", authMiddleware, async (req, res) => {
  try {
    const reminderId = Number(req.params.id);
    if (!reminderId) {
      return res.status(400).json({ ok: false, message: "ID do lembrete inválido." });
    }

    const deleteResult = await query("DELETE FROM reminders WHERE id = ? AND user_id = ?", [
      reminderId,
      req.authUser.id,
    ]);

    if (!deleteResult.affectedRows) {
      return res.status(404).json({ ok: false, message: "Lembrete não encontrado para exclusão." });
    }

    return res.json({ ok: true, message: "Lembrete removido com sucesso." });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao remover lembrete.", error: String(error) });
  }
});

app.post("/api/prescription-requests", authMiddleware, async (req, res) => {
  try {
    const { medicine, details } = req.body ?? {};
    const normalizedMedicine = String(medicine ?? "").trim();
    const normalizedDetails = String(details ?? "").trim();

    if (!normalizedMedicine) {
      return res.status(400).json({ ok: false, message: "Informe o medicamento para solicitar receita." });
    }

    await query(
      "INSERT INTO prescription_requests (user_id, medicine, details) VALUES (?, ?, ?)",
      [req.authUser.id, normalizedMedicine, normalizedDetails || null],
    );

    return res.status(201).json({ ok: true, message: "Solicitação de receita enviada com sucesso." });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Erro ao solicitar receita.", error: String(error) });
  }
});

async function startServer() {
  try {
    await initDatabase();
    await testConnection();
    app.listen(port, () => {
      console.log(`API rodando em http://localhost:${port}`);
    });
  } catch (error) {
    console.error("Falha ao iniciar API:", error);
    process.exit(1);
  }
}

void startServer();
