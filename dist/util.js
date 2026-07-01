export function ok(data) {
    const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
    return { content: [{ type: "text", text }] };
}
export function fail(error) {
    const e = error;
    const message = e?.message ?? (typeof error === "string" ? error : "Unknown error");
    const details = e?.errors ? `\nDetails: ${JSON.stringify(e.errors)}` : "";
    return {
        isError: true,
        content: [{ type: "text", text: `Error: ${message}${details}` }],
    };
}
/** Wraps a tool handler so thrown errors become structured MCP error results. */
export function guard(fn) {
    return async (args) => {
        try {
            return await fn(args);
        }
        catch (err) {
            return fail(err);
        }
    };
}
/** True for MIME types whose bytes are safe to return inline as UTF-8 text. */
export function isTextual(mime) {
    return (mime.startsWith("text/") ||
        mime === "application/json" ||
        mime === "application/xml" ||
        mime === "application/csv" ||
        mime.endsWith("+json") ||
        mime.endsWith("+xml"));
}
