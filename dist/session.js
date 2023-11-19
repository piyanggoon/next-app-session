import { nanoid } from 'nanoid';
import { MemoryStore } from './memory';
import { cookies } from 'next/headers';
import { RequestCookies } from 'next/dist/compiled/@edge-runtime/cookies';
export default function nextAppSession(options) {
    const store = options.store || new MemoryStore();
    return (req) => new AppSession(store, options, req);
}
export class AppSession {
    static instance;
    req;
    store;
    sid;
    name;
    secret;
    genid;
    cookieOpts;
    touchAfter;
    constructor(store, options, req) {
        if (!req && typeof window !== 'undefined') {
            throw new Error('Wrong implementation, please check the next-app-session docs for more info');
        }
        this.req = req;
        this.store = store;
        this.name = options?.name || 'sid';
        this.secret = options?.secret;
        this.genid = options?.genid || nanoid;
        this.cookieOpts = options?.cookie;
        this.touchAfter = options?.touchAfter;
        return this;
    }
    getCookie(name) {
        if (this.req?.cookies) {
            return this.req.cookies[name];
        }
        return cookies().get(name)?.value;
    }
    setCookie(name, value, cookieOpts) {
        if (this.req?.headers) {
            // @ts-ignore
            const headers = new Headers(this.req.headers);
            const cookies = new RequestCookies(headers);
            cookies.set(name, value);
        }
        return cookies().set(name, value, cookieOpts);
    }
    async _getID() {
        return await this.decode(this.getCookie(this.name));
    }
    async _initID() {
        let id = await this._getID();
        if (!id && this.genid) {
            id = this.genid();
        }
        this.sid = id || '';
    }
    async sign(input, secret) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(input);
            const secretKey = encoder.encode(secret);
            const subtleCrypto = crypto.subtle;
            const algorithm = { name: 'HMAC', hash: 'SHA-256' };
            const cryptoKey = await subtleCrypto.importKey('raw', secretKey, algorithm, false, ['sign']);
            const signature = await subtleCrypto.sign(algorithm, cryptoKey, data);
            const signatureArray = Array.from(new Uint8Array(signature));
            const signatureString = signatureArray.map(byte => String.fromCharCode(byte)).join('');
            const base64Signature = btoa(signatureString);
            return input + '.' + base64Signature.replace(/\=+$/, '');
        }
        catch {
            return null;
        }
    }
    async unsign(input, secret) {
        try {
            const encoder = new TextEncoder();
            const inputParts = input.split('.');
            const val = inputParts[0];
            const base64Signature = inputParts[1];
            const signature = atob(base64Signature);
            const data = encoder.encode(val);
            const signatureArray = Array.from(signature).map(char => char.charCodeAt(0));
            const signatureBytes = new Uint8Array(signatureArray);
            const subtleCrypto = crypto.subtle;
            const algorithm = { name: 'HMAC', hash: 'SHA-256' };
            const secretKey = encoder.encode(secret);
            const cryptoKey = await subtleCrypto.importKey('raw', secretKey, algorithm, false, ['verify']);
            const isValid = await subtleCrypto.verify(algorithm, cryptoKey, signatureBytes, data);
            return isValid ? val : null;
        }
        catch {
            return null;
        }
    }
    async encode(sid) {
        if (!this.secret || this.secret == '')
            return sid;
        return sid ? 's:' + await this.sign(sid, this.secret || '') : '';
    }
    async decode(raw) {
        if (!raw || !this.secret || this.secret == '')
            return raw || null;
        return await this.unsign(raw.slice(2), this.secret || '');
    }
    async all() {
        await this._initID();
        const data = await this.store?.get(this.sid);
        return data ?? {};
    }
    async get(key) {
        const data = await this.all();
        return data?.[key] ?? null;
    }
    async has(key) {
        const data = await this.all();
        return !!data?.[key] && data?.[key] !== '';
    }
    async set(key, value) {
        let data = await this.all();
        if (!data) {
            data = {};
        }
        data[key] = value;
        await this.setAll(data);
    }
    async setAll(data) {
        await this._initID();
        const existingID = await this._getID();
        if (!existingID || existingID == '') {
            await this.setCookie(this.name, this.encode(this.sid), {
                path: this.cookieOpts?.path || '/',
                httpOnly: this.cookieOpts?.httpOnly ?? true,
                domain: this.cookieOpts?.domain || undefined,
                sameSite: this.cookieOpts?.sameSite,
                secure: this.cookieOpts?.secure || false,
                maxAge: this.cookieOpts?.maxAge || undefined,
                expires: this.cookieOpts?.expires || undefined
            });
        }
        await this.store.set(this.sid, { ...data });
    }
    async destroy(key) {
        if (key) {
            const data = (await this.all()) || {};
            delete data[key];
            await this.setAll(data);
        }
        else {
            await this.setAll({});
        }
    }
}
