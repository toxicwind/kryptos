// @estate/keypool — freeinference concurrency-permit client.
//
// History: the freeinference route hard-fetched a coordinator at
// http://127.0.0.1:25250/acquire OUTSIDE any error handling. When that
// coordinator service retired (nothing listens on :25250 since the estate
// consolidation), every freeinference forward died with
// 502 ECONNREFUSED before reaching the upstream — which cascaded:
// mimetite's health probes 502'd → freeinference marked unhealthy →
// deepseek-v4-flash lost its only serving provider → tau's Code lane
// answered "no routing candidate could grant a slot".
//
// Contract (tested here):
// - Connection-level failure (ECONNREFUSED, timeout) acquiring a permit
//   DEGRADES to permit-less forwarding (null) — the coordinator is an
//   optimization, not an availability gate. mimetite's pgate enforces
//   freeinference's 2-slot concurrency law upstream of keypool.
// - A coordinator that ANSWERS with {ok:false} still sheds (503) — that is
//   a deliberate concurrency decision, not an outage.
// - release() is fire-and-forget: never throws, never blocks.

import { logWarn } from "./log.ts";

export interface PermitClient {
	/** Acquire a concurrency permit. Returns null when the coordinator is
	 *  unreachable (degraded, proceed without permit). Throws {status:503}
	 *  when the coordinator deliberately sheds. */
	acquire(model: string, sessionId: string | null): Promise<string | null>;
	/** Fire-and-forget release. Never throws. */
	release(requestId: string, model: string): void;
}

type FetchLike = typeof fetch;

function isConnRefused(e: unknown): boolean {
	const msg = String((e as Error)?.cause ?? (e as Error)?.message ?? e);
	return /ECONNREFUSED|ConnectionRefused|Unable to connect|fetch failed|ECONNRESET|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH/i.test(
		msg,
	);
}

export function makePermitClient(baseUrl: string, fetcher: FetchLike = fetch): PermitClient {
	return {
		async acquire(model, sessionId) {
			let resp: Response;
			try {
				resp = await fetcher(`${baseUrl}/acquire`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({
						model: model || "unknown",
						requestId: crypto.randomUUID(),
						sessionId,
						priority: 0,
					}),
					// Bound the coordinator hop: a hung coordinator must not
					// become a hung lane (the old path had no timeout at all).
					signal: AbortSignal.timeout(2000),
				});
			} catch (e) {
				logWarn(
					`[keypool] coordinator unreachable (${String(e).slice(0, 120)}); proceeding without permit`,
				);
				return null;
			}
			const data = (await resp.json().catch(() => ({ ok: false }))) as {
				ok?: boolean;
				requestId?: string;
				error?: string;
				retryAfter?: number;
			};
			if (!data.ok) {
				throw Object.assign(
					new Error(data.error || "coordinator acquire failed"),
					{ status: 503, retryAfter: data.retryAfter || 1000 },
				);
			}
			return data.requestId ?? null;
		},
		release(requestId, model) {
			fetcher(`${baseUrl}/release`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ requestId, model: model || "unknown" }),
			}).catch(() => {});
		},
	};
}

export { isConnRefused };
