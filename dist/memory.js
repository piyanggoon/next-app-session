export class MemoryStore {
    store;
    _instance;
    constructor() {
        if (this._instance) {
            return this._instance;
        }
        if (typeof global !== 'undefined') {
            if (global.sessionMemoryStore) {
                return global.sessionMemoryStore;
            }
        }
        this.store = new Map();
        this._instance = this;
        if (typeof global !== 'undefined') {
            global.sessionMemoryStore = this;
        }
        return this;
    }
    async get(sid) {
        const sess = this.store.get(sid);
        if (sess) {
            const session = JSON.parse(sess, (key, value) => {
                if (key === 'expires')
                    return new Date(value);
                return value;
            });
            // destroy expired session
            if (session.cookie?.expires &&
                session.cookie.expires.getTime() <= Date.now()) {
                await this.destroy(sid);
                return null;
            }
            return session;
        }
        return null;
    }
    async set(sid, sess) {
        this.store.set(sid, JSON.stringify(sess));
    }
    async destroy(sid) {
        this.store.delete(sid);
    }
    async touch(sid, sess) {
        this.store.set(sid, JSON.stringify(sess));
    }
}
