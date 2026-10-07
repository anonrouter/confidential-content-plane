import Fastify from 'fastify';
import { describe, it, expect } from 'vitest';
import { installServiceLifecycle, serviceIsReady } from '../../src/operations/serviceLifecycle.js';

describe('service draining', () => {
  it('marks unready immediately and waits for an admitted response to finish', async () => {
    const server = Fastify();
    const lifecycle = installServiceLifecycle(server, { drainDelayMs: 10 });
    let admit!: () => void;
    let finish!: () => void;
    const admitted = new Promise<void>(r => { admit = r; });
    const completion = new Promise<void>(r => { finish = r; });
    server.get('/work', async () => { admit(); await completion; return { done: true }; });
    await server.listen({ host: '127.0.0.1', port: 0 });
    const address = server.server.address();
    if (!address || typeof address === 'string') throw new Error('missing listener');
    const response = fetch(`http://127.0.0.1:${address.port}/work`);
    try {
    await admitted;
    const closing = lifecycle.drain();
    expect(serviceIsReady(server)).toBe(false);
    expect(lifecycle.drain()).toBe(closing);
    let closed = false;
    void closing.then(() => { closed = true; });
    await new Promise(r => setTimeout(r, 30));
    expect(closed).toBe(false);
    finish();
    expect(await (await response).json()).toEqual({ done: true });
    await closing;
    } finally { finish(); await lifecycle.drain(); }
  });
  it('refuses arbitrary readiness-file paths', async () => {
    const server = Fastify();
    expect(() => installServiceLifecycle(server, { readyFile: '/tmp/anything' })).toThrow();
    await server.close();
  });
  it('keeps a starting slot unready until the host admits it', async () => {
    const server = Fastify();
    installServiceLifecycle(server, { readyFile: '/run/anonrouter/control-slots/a/status/serving' });
    expect(serviceIsReady(server)).toBe(false);
    await server.close();
  });
});
