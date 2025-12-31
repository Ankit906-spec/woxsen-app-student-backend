import { google } from "googleapis";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const DRIVE_CLIENT_EMAIL = process.env.GOOGLE_DRIVE_CLIENT_EMAIL;
const DRIVE_PRIVATE_KEY = process.env.GOOGLE_DRIVE_PRIVATE_KEY ? process.env.GOOGLE_DRIVE_PRIVATE_KEY.replace(/\\n/g, "\n").replace(/^"(.*)"$/, "$1") : null;
const DRIVE_FOLDER_ID = process.env.GOOGLE_DRIVE_FOLDER_ID;

console.log("Email:", DRIVE_CLIENT_EMAIL);
console.log("Folder ID:", DRIVE_FOLDER_ID);
console.log("Private Key present:", !!DRIVE_PRIVATE_KEY);

if (!DRIVE_CLIENT_EMAIL || !DRIVE_PRIVATE_KEY || !DRIVE_FOLDER_ID) {
    console.error("Missing credentials");
    process.exit(1);
}

const auth = new google.auth.JWT({
    email: DRIVE_CLIENT_EMAIL,
    key: DRIVE_PRIVATE_KEY,
    scopes: ["https://www.googleapis.com/auth/drive"]
});

const drive = google.drive({ version: "v3", auth });

async function test() {
    try {
        console.log("Testing folder access...");
        const res = await drive.files.get({
            fileId: DRIVE_FOLDER_ID,
            fields: "id, name, capabilities"
        });
        console.log("Folder found:", res.data.name);
        console.log("Capabilities:", res.data.capabilities);

        if (!res.data.capabilities.canAddChildren) {
            console.error("CRITICAL: Service account does NOT have permission to add files to this folder.");
        } else {
            console.log("SUCCESS: Service account HAS permission to add files.");

            console.log("Attempting to create a small test file...");
            const dummyStream = new (await import("stream")).PassThrough();
            dummyStream.end("Test content");

            const createRes = await drive.files.create({
                requestBody: {
                    name: "test-upload-" + Date.now() + ".txt",
                    parents: [DRIVE_FOLDER_ID]
                },
                media: {
                    mimeType: "text/plain",
                    body: dummyStream
                },
                fields: "id",
                supportsAllDrives: true // Adding this just in case
            });
            console.log("SUCCESS: Created test file with ID:", createRes.data.id);

            // Cleanup
            await drive.files.delete({ fileId: createRes.data.id, supportsAllDrives: true });
            console.log("SUCCESS: Deleted test file.");
        }
    } catch (err) {
        console.error("Test failed:", err.message);
        if (err.response) {
            console.error("Detailed Error:", JSON.stringify(err.response.data));
        }
    }
}

test();
