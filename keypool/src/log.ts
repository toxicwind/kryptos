// @estate/keypool — log helpers. Zero-dependency stderr sink so modules
// without a logger still emit structured, dedupe-friendly lines.

export function logWarn(message: string): void {
	console.error(`WARN ${message}`);
}

export function logInfo(message: string): void {
	console.log(`INFO ${message}`);
}
