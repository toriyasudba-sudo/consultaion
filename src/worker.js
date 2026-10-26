const enc = new TextEncoder();
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json' } });
const hex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');

async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', typeof key === 'string' ? enc.encode(key) : key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}

// Проверка подписи Telegram initData -> объект пользователя или null
async function verify(initData, token) {
  if (!initData) return null;
  const p = new URLSearchParams(initData);
  const hash = p.get('hash');
  p.delete('hash');
  const check = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join('\n');
  const secret = await hmac('WebAppData', token);
  if (hex(await hmac(secret, check)) !== hash) return null;
  if (Date.now() / 1000 - Number(p.get('auth_date')) > 86400) return null;
  try { return JSON.parse(p.get('user')); } catch { return null; }
}

const get = async (env, k) => JSON.parse((await env.DB.get(k)) || '[]');
const put = (env, k, v) => env.DB.put(k, JSON.stringify(v));
const clip = (s, n = 1000) => String(s || '').trim().slice(0, n);

export default {
  async fetch(req, env, ctx) {
    const p = new URL(req.url).pathname;
    const post = req.method === 'POST';
    try {
      const user = await verify(req.headers.get('X-Init-Data') || '', env.BOT_TOKEN);
      const owner = !!user && String(user.id) === String(env.OWNER_ID);

      if (p === '/api/me') return json({ owner });

      if (p === '/api/slots') {
        return json({ slots: (await get(env, 'slots')).filter(s => !s.booked) });
      }

      if (p === '/api/book' && post) {
        if (!user) return json({ error: 'Откройте приложение через Telegram' }, 401);
        const b = await req.json();
        const name = clip(b.name, 100);
        if (!name) return json({ error: 'Введите имя ребёнка' }, 400);
        const slots = await get(env, 'slots');
        const slot = slots.find(s => s.id === b.slotId);
        if (!slot || slot.booked) return json({ error: 'Это время уже занято' }, 409);
        slot.booked = true;
        const r = {
          id: 'r' + Date.now(), studentName: name,
          telegram: user.username ? '@' + user.username : [user.first_name, user.last_name].filter(Boolean).join(' '),
          tgId: user.id, phone: clip(b.phone, 40) || 'Не указан',
          slotText: `${slot.date} ${slot.time}`,
          success: clip(b.success) || 'Не указано', issues: clip(b.issues) || 'Не указано',
          topics: clip(b.topics) || 'Не указано', expectations: clip(b.expectations) || 'Не указано',
          timestamp: new Date().toISOString()
        };
        const reqs = await get(env, 'requests');
        reqs.unshift(r);
        await put(env, 'slots', slots);
        await put(env, 'requests', reqs);
        const text = `🔔 Новая запись на консультацию\nРебёнок: ${r.studentName}\nВремя: ${r.slotText}\nКонтакты: ${r.telegram} | ${r.phone}\n\nПолучается и радует: ${r.success}\nТревожит / непросто: ${r.issues}\nВажно обсудить: ${r.topics}\nОжидания от встречи: ${r.expectations}`;
        ctx.waitUntil(fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: env.OWNER_ID, text })
        }));
        return json({ ok: true, slotText: r.slotText });
      }

      if (p === '/api/admin' && post) {
        const b = await req.json();
        if (!owner || b.password !== env.ADMIN_PASSWORD) return json({ error: 'Доступ запрещён' }, 403);
        let slots = await get(env, 'slots');
        let reqs = await get(env, 'requests');
        if (b.action === 'addSlot' && b.date && b.time) slots.push({ id: 's' + Date.now(), date: clip(b.date, 10), time: clip(b.time, 5), booked: false });
        if (b.action === 'delSlot') slots = slots.filter(s => s.id !== b.id);
        if (b.action === 'delReq') reqs = reqs.filter(r => r.id !== b.id);
        if (b.action === 'clear') reqs = [];
        slots.sort((a, c) => (a.date + a.time).localeCompare(c.date + c.time));
        await put(env, 'slots', slots);
        await put(env, 'requests', reqs);
        return json({ slots, requests: reqs });
      }

      return json({ error: 'Не найдено' }, 404);
    } catch (e) {
      return json({ error: 'Ошибка сервера' }, 500);
    }
  }
};
