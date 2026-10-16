import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, createApi, safeRedirect, SessionExpiredError } from './client';

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn(async () => new Response(body === undefined ? null : JSON.stringify(body), { status }));
  vi.stubGlobal('fetch', fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('createApi', () => {
  it('redirects to the login on 401 and does not retry', async () => {
    const fetchFn = mockFetch(401, { error: 'Anmeldung erforderlich.' });
    const navigate = vi.fn();

    await expect(createApi(navigate).myAccess()).rejects.toBeInstanceOf(SessionExpiredError);
    expect(navigate).toHaveBeenCalledWith('/auth/login');
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('surfaces the server error message', async () => {
    mockFetch(403, { error: 'duration exceeds AccessProfile maximum' });
    const err = await createApi(vi.fn())
      .createAccess({ namespace: 'n', accessProfile: 'p', duration: '9h', reason: 'INC-1' })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(403);
    expect((err as ApiError).message).toBe('duration exceeds AccessProfile maximum');
  });

  it('sends unsafe requests as same-origin JSON', async () => {
    const fetchFn = mockFetch(200, { status: 'revoked' });
    await createApi(vi.fn()).revokeSession('team/../a', 'bgs/../x');

    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/v1/namespaces/team%2F..%2Fa/sessions/bgs%2F..%2Fx/revoke');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('same-origin');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
  });

  it('reports an unreachable server without throwing a raw TypeError', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Promise.reject(new TypeError('Failed to fetch'))));
    const err = await createApi(vi.fn()).me().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(0);
  });
});

describe('safeRedirect', () => {
  it.each([
    [undefined, '/logged-out.html'],
    ['/logged-out.html', '/logged-out.html'],
    ['https://idp.example.com/logout?x=1', 'https://idp.example.com/logout?x=1'],
    ['javascript:alert(1)', '/logged-out.html'],
    ['//evil.example.com', '/logged-out.html'],
    ['http://idp.example.com/logout', '/logged-out.html'],
  ])('%s -> %s', (input, expected) => {
    expect(safeRedirect(input)).toBe(expected);
  });
});
