const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
    }
  });

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64url(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function hmac(data, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return base64url(
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(data)
    )
  );
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return base64url(bits);
}

async function createToken(user, secret) {
  const payload = {
    username: user.username,
    role: user.role,
    exp: Date.now() + 24 * 60 * 60 * 1000
  };

  const body = base64url(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  const signature = await hmac(body, secret);

  return `${body}.${signature}`;
}

async function verifyToken(token, secret) {
  try {
    const [body, signature] = token.split(".");

    if (!body || !signature) return null;

    const expected = await hmac(body, secret);

    if (signature !== expected) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64url(body))
    );

    if (payload.exp < Date.now()) return null;

    return payload;
  } catch {
    return null;
  }
}

async function supabase(env, path, options = {}) {
  const response = await fetch(
    `${env.SUPABASE_URL}/rest/v1/${path}`,
    {
      ...options,
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    }
  );

  return response;
}

async function handleApi(request, env) {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  const url = new URL(request.url);
  const path = url.pathname;

  // LOGIN ADMIN
  if (path === "/api/login" && request.method === "POST") {
    const { username, password } = await request.json();

    if (!username || !password) {
      return json({ error: "Username dan password wajib diisi." }, 400);
    }

    const result = await supabase(
      env,
      `admins?username=eq.${encodeURIComponent(username)}&select=*`
    );

    if (!result.ok) {
      return json({ error: "Gagal mengakses database." }, 500);
    }

    const admins = await result.json();

    if (!admins.length) {
      return json({ error: "Username atau password salah." }, 401);
    }

    const admin = admins[0];

    const passwordHash = await hashPassword(
      password,
      admin.salt
    );

    if (passwordHash !== admin.password_hash) {
      return json({ error: "Username atau password salah." }, 401);
    }

    const token = await createToken(admin, env.AUTH_SECRET);

    return json({
      success: true,
      token,
      username: admin.username,
      role: admin.role
    });
  }

  // CEK LOGIN
  if (path === "/api/me" && request.method === "GET") {
    const auth = request.headers.get("Authorization");

    if (!auth?.startsWith("Bearer ")) {
      return json({ loggedIn: false }, 401);
    }

    const user = await verifyToken(
      auth.slice(7),
      env.AUTH_SECRET
    );

    if (!user) {
      return json({ loggedIn: false }, 401);
    }

    return json({
      loggedIn: true,
      username: user.username,
      role: user.role
    });
  }

  // SETUP ADMIN PERTAMA
  if (path === "/api/setup-admin" && request.method === "POST") {
    const setupKey = request.headers.get("X-Setup-Key");

    if (!setupKey || setupKey !== env.SETUP_KEY) {
      return json({ error: "Setup key salah." }, 403);
    }

    const { username, password, role = "admin" } =
      await request.json();

    if (!username || !password) {
      return json({ error: "Username dan password wajib." }, 400);
    }

    if (password.length < 8) {
      return json(
        { error: "Password minimal 8 karakter." },
        400
      );
    }

    const salt = crypto.randomUUID();

    const passwordHash = await hashPassword(
      password,
      salt
    );

    const result = await supabase(
      env,
      "admins",
      {
        method: "POST",
        headers: {
          Prefer: "return=minimal"
        },
        body: JSON.stringify({
          username,
          password_hash: passwordHash,
          salt,
          role
        })
      }
    );

    if (!result.ok) {
      return json(
        { error: "Gagal membuat admin." },
        500
      );
    }

    return json({
      success: true,
      message: "Admin berhasil dibuat."
    });
  }

  // TAMBAH ADMIN
  if (path === "/api/admins" && request.method === "POST") {
    const auth = request.headers.get("Authorization");

    if (!auth?.startsWith("Bearer ")) {
      return json({ error: "Belum login." }, 401);
    }

    const current = await verifyToken(
      auth.slice(7),
      env.AUTH_SECRET
    );

    if (!current || current.role !== "owner") {
      return json(
        { error: "Hanya owner yang boleh menambah admin." },
        403
      );
    }

    const { username, password, role = "admin" } =
      await request.json();

    if (!username || !password) {
      return json({ error: "Data belum lengkap." }, 400);
    }

    const salt = crypto.randomUUID();

    const passwordHash = await hashPassword(
      password,
      salt
    );

    const result = await supabase(
      env,
      "admins",
      {
        method: "POST",
        headers: {
          Prefer: "return=minimal"
        },
        body: JSON.stringify({
          username,
          password_hash: passwordHash,
          salt,
          role
        })
      }
    );

    if (!result.ok) {
      return json(
        { error: "Gagal menambah admin." },
        500
      );
    }

    return json({
      success: true,
      message: "Admin berhasil ditambahkan."
    });
  }

  // VOTE
  if (path === "/api/vote" && request.method === "POST") {
    const { username, guildId } = await request.json();

    if (!username || !guildId) {
      return json(
        { error: "Username dan server wajib diisi." },
        400
      );
    }

    const existing = await supabase(
      env,
      `votes?username=eq.${encodeURIComponent(username)}&guild_id=eq.${encodeURIComponent(guildId)}&select=*`
    );

    if (!existing.ok) {
      return json(
        { error: "Gagal mengecek voting." },
        500
      );
    }

    const votes = await existing.json();

    if (votes.length) {
      const lastVote = new Date(votes[0].last_vote).getTime();
      const cooldown = 24 * 60 * 60 * 1000;
      const remaining = cooldown - (Date.now() - lastVote);

      if (remaining > 0) {
        return json({
          success: false,
          cooldown: true,
          remainingMs: remaining
        }, 429);
      }

      await supabase(
        env,
        `votes?id=eq.${votes[0].id}`,
        {
          method: "PATCH",
          body: JSON.stringify({
            last_vote: new Date().toISOString(),
            total_votes: votes[0].total_votes + 1,
            points: votes[0].points + 1
          })
        }
      );
    } else {
      await supabase(
        env,
        "votes",
        {
          method: "POST",
          headers: {
            Prefer: "return=minimal"
          },
          body: JSON.stringify({
            username,
            guild_id: guildId,
            last_vote: new Date().toISOString(),
            total_votes: 1,
            points: 1
          })
        }
      );
    }

    return json({
      success: true,
      points: 1,
      message: "Vote berhasil! +1 point."
    });
  }

  return json({ error: "API tidak ditemukan." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      return handleApi(request, env);
    }

    return env.ASSETS.fetch(request);
  }
};
