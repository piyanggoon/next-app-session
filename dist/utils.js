import { promisify } from 'util';
export function promisifyStore(connectStore) {
    return {
        get: promisify(connectStore.get).bind(connectStore),
        set: promisify(connectStore.set).bind(connectStore),
        destroy: promisify(connectStore.destroy).bind(connectStore),
        ...(connectStore.touch && {
            touch: promisify(connectStore.touch).bind(connectStore)
        })
    };
}
