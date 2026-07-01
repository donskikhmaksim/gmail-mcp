import { google } from "googleapis";
const GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/documents.readonly",
];
function buildAuthClient(auth) {
    if (auth.mode === "oauth") {
        const oauth2 = new google.auth.OAuth2(auth.clientId, auth.clientSecret);
        oauth2.setCredentials({ refresh_token: auth.refreshToken });
        return oauth2;
    }
    return new google.auth.GoogleAuth({
        credentials: auth.credentials,
        scopes: GOOGLE_SCOPES,
    });
}
export function createGoogleClients(authConfig) {
    const auth = buildAuthClient(authConfig);
    return {
        gmail: google.gmail({ version: "v1", auth }),
        drive: google.drive({ version: "v3", auth }),
        docs: google.docs({ version: "v1", auth }),
    };
}
