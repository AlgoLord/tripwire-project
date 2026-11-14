// Canonical implementation lives in contract/sentry/verifier.ts.
// Keep this compatibility entry point so older imports do not drift into
// a second, independently maintained verifier implementation.
export * from "../../contract/sentry/verifier";
