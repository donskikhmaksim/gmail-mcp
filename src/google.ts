import { google, gmail_v1, drive_v3, docs_v1 } from "googleapis";
import { GoogleAuthConfig } from "./config.js";

const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/drive",
  "https://www.googleapis.com/auth/documents.readonly",
];

export interface GoogleClients {
  gmail: gmail_v1.Gmail;
  drive: drive_v3.Drive;
  docs: docs_v1.Docs;
  /**
   * A fresh OAuth access token for raw REST calls the googleapis client cannot
   * make on our behalf — currently the resumable upload handshake, which has to
   * be issued by hand so the client can send the bytes itself.
   */
  accessToken(): Promise<string>;
}

function buildAuthClient(auth: GoogleAuthConfig) {
  if (auth.mode === "oauth") {
    const oauth2 = new google.auth.OAuth2(auth.clientId, auth.clientSecret);
    oauth2.setCredentials({ refresh_token: auth.refreshToken });
    return oauth2;
  }
  return new google.auth.GoogleAuth({
    credentials: auth.credentials as Record<string, string>,
    scopes: GOOGLE_SCOPES,
  });
}

export function createGoogleClients(authConfig: GoogleAuthConfig): GoogleClients {
  const auth = buildAuthClient(authConfig);
  return {
    gmail: google.gmail({ version: "v1", auth }),
    drive: google.drive({ version: "v3", auth }),
    docs: google.docs({ version: "v1", auth }),
    async accessToken(): Promise<string> {
      // OAuth2Client resolves to { token }, GoogleAuth to a plain string.
      const t = await auth.getAccessToken();
      const token = typeof t === "string" ? t : t?.token;
      if (!token) throw new Error("Could not obtain a Google access token for this account.");
      return token;
    },
  };
}
