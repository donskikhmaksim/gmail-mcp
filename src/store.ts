// Stub — snooze/DB features not available in standalone gmail-mcp.
export interface PgStore {
  addSnooze(args: { userToken: string; accountName: string; messageId: string; subject?: string; unsnoozeAt: Date }): Promise<void>;
}
