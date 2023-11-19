import {
  CookieOptions,
  Options,
  SessionData,
  SessionHandler,
  SessionRecord,
  Store
} from './types';
import { nanoid } from 'nanoid';
import { MemoryStore } from './memory';
import { cookies } from 'next/headers';

// import { RequestCookies } from 'next/dist/compiled/@edge-runtime/cookies';
import { NextApiRequest } from 'next';
import { RequestCookies } from 'next/dist/compiled/@edge-runtime/cookies';

export default function nextAppSession<T extends SessionRecord>(
  options: Options
): (req?: NextApiRequest) => AppSession<T> {
  const store = options.store || new MemoryStore();
  return (req?: NextApiRequest) => new AppSession<T>(store, options, req);
}

export class AppSession<T extends SessionRecord = SessionRecord>
  implements SessionHandler<T>
{
  static instance: AppSession;
  protected req?: NextApiRequest;
  protected store: Store;
  protected sid: string;
  protected name: string;
  protected secret?: string;
  protected genid: () => string;
  protected cookieOpts?: Partial<CookieOptions>;
  protected touchAfter?: boolean;

  constructor(store: Store, options: Options, req?: NextApiRequest) {
    if (!req && typeof window !== 'undefined') {
      throw new Error(
        'Wrong implementation, please check the next-app-session docs for more info'
      );
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

  private getCookie(name: string) {
    if (this.req?.cookies) {
      return this.req.cookies[name];
    }
    return cookies().get(name)?.value;
  }

  private setCookie(name: string, value: any, cookieOpts?: any) {
    if (this.req?.headers) {
      // @ts-ignore
      const headers = new Headers(this.req.headers);
      const cookies = new RequestCookies(headers);
      cookies.set(name, value);
    }
    return cookies().set(name, value, cookieOpts);
  }

  private async _getID(): Promise<string | null | undefined> {
    return await this.decode(this.getCookie(this.name));
  }

  private async _initID() {
    let id = await this._getID();
    if (!id && this.genid) {
      id = this.genid();
    }
    this.sid = id || '';
  }

  private async sign(input: string, secret: string): Promise<string | null> {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(input);
      const secretKey = encoder.encode(secret);
  
      const subtleCrypto = crypto.subtle;
      const algorithm = { name: 'HMAC', hash: 'SHA-256' };
      const cryptoKey = await subtleCrypto.importKey('raw', secretKey, algorithm, false, ['sign']);
  
      const signature = await subtleCrypto.sign(algorithm, cryptoKey, data)
  
      const signatureArray = Array.from(new Uint8Array(signature));
      const signatureString = signatureArray.map(byte => String.fromCharCode(byte)).join('');
      const base64Signature = btoa(signatureString);
  
      return input + '.' + base64Signature.replace(/\=+$/, '');
    } catch {
      return null;
    }
  }

  private async unsign(input: string, secret: string): Promise<string | null> {
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
  
      const cryptoKey = await  subtleCrypto.importKey('raw', secretKey, algorithm, false, ['verify'])
      const isValid = await subtleCrypto.verify(algorithm, cryptoKey, signatureBytes, data);
  
      return isValid ? val : null;
    } catch {
      return null;
    }
  }

  private async encode(sid: string): Promise<string> {
    if (!this.secret || this.secret == '') return sid;
    return sid ? 's:' + await this.sign(sid, this.secret || '') : '';
  }

  private async decode(raw: string | null | undefined): Promise<string | null> {
    if (!raw || !this.secret || this.secret == '') return raw || null;
    return await this.unsign(raw.slice(2), this.secret || '');
  }

  async all(): Promise<SessionData<T> | null | undefined> {
    await this._initID();
    const data = await this.store?.get(this.sid);
    return data ?? {};
  }
  async get(key: string | keyof T): Promise<any> {
    const data = await this.all();
    return data?.[key] ?? null;
  }
  async has(key: string | keyof T): Promise<boolean> {
    const data = await this.all();
    return !!data?.[key] && data?.[key] !== '';
  }
  async set(key: string | keyof T, value: any): Promise<void> {
    let data: any = await this.all();
    if (!data) {
      data = {};
    }
    data[key] = value;
    await this.setAll(data);
  }
  async setAll(data: T): Promise<void> {
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
  async destroy(key?: string | keyof T | undefined): Promise<void> {
    if (key) {
      const data = (await this.all()) || ({} as T);
      delete data[key];
      await this.setAll(data);
    } else {
      await this.setAll({} as T);
    }
  }
}
