export class CookieJar {
  #cookies = [];

  set({ name, value, domain, path = "/", secure = true }) {
    const cookie = { name, value, domain: domain.replace(/^\./, "").toLowerCase(), path, secure };
    this.#cookies = this.#cookies.filter(item => !(item.name === cookie.name && item.domain === cookie.domain && item.path === cookie.path));
    this.#cookies.push(cookie);
  }

  store(url, response) {
    const source = new URL(url);
    const values = typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [response.headers.get("set-cookie")].filter(Boolean);
    const forwarded = response.headers.get("aone-set-cookie");
    if (forwarded) values.push(...forwarded.split(/,(?=[^;,]+=)/));

    for (const value of values) {
      const parts = value.split(";").map(part => part.trim());
      const equals = parts[0].indexOf("=");
      if (equals < 1) continue;
      const cookie = {
        name: parts[0].slice(0, equals),
        value: parts[0].slice(equals + 1),
        domain: source.hostname,
        path: "/",
        secure: false
      };
      for (const attribute of parts.slice(1)) {
        const [rawName, ...rest] = attribute.split("=");
        const name = rawName.toLowerCase();
        if (name === "domain" && rest.length) cookie.domain = rest.join("=").replace(/^\./, "").toLowerCase();
        if (name === "path" && rest.length) cookie.path = rest.join("=");
        if (name === "secure") cookie.secure = true;
      }
      this.set(cookie);
    }
  }

  header(url) {
    const target = new URL(url);
    return this.#cookies
      .filter(cookie => (target.hostname === cookie.domain || target.hostname.endsWith(`.${cookie.domain}`))
        && target.pathname.startsWith(cookie.path)
        && (!cookie.secure || target.protocol === "https:"))
      .map(cookie => `${cookie.name}=${cookie.value}`)
      .join("; ");
  }
}
