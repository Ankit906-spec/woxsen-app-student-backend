import express from "express";
import cors from "cors";
import path from "path";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import mongoose from "mongoose";
import { v2 as cloudinary } from "cloudinary";
import { v4 as uuidv4 } from "uuid";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import { google } from "googleapis";
import { PassThrough } from "stream";
import nodemailer from "nodemailer"; // Ensure this is installed or use dynamic import if strict

dotenv.config();

// --- Email Config (Brevo SMTP) ---
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const ADMIN_EMAIL = "ankityadav94698@gmail.com";

const transporter = nodemailer.createTransport({
  host: "smtp-relay.brevo.com",
  port: 465,
  secure: true, // Use SSL for better reliability
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  },
  debug: true, // Show debug output
  logger: true // Log information in console
});

// Verify connection configuration on startup
if (EMAIL_USER && EMAIL_PASS) {
  transporter.verify((error, success) => {
    if (error) {
      console.error("❌ SMTP Connection Error:", error.message);
      if (error.response) console.error("   SMTP Response:", error.response);
    } else {
      console.log("✅ SMTP Server is ready to take our messages");
    }
  });
}

const otpMap = new Map(); // Store OTPs: email -> { code, expires }

async function sendEmail(to, subject, text) {
  if (!EMAIL_USER || !EMAIL_PASS) {
    console.log("==================================================");
    console.log(`[MOCK EMAIL] To: ${to}`);
    console.log(`[MOCK EMAIL] Subject: ${subject}`);
    console.log(`[MOCK EMAIL] Body: ${text}`);
    console.log("==================================================");
    return;
  }
  try {
    console.log(`[Email] Sending to ${to}...`);
    const info = await transporter.sendMail({ from: EMAIL_USER, to, subject, text });
    console.log(`✅ [Email] Sent successfully: ${info.messageId}`);
  } catch (err) {
    console.error("❌ [Email] Send error:", err.message);
    if (err.response) console.error("   [Email] SMTP Response:", err.response);

    // Fallback log so the developer can still see the OTP in console
    console.warn("--------------------------------------------------");
    console.warn(`[OTP FALLBACK LOG] To: ${to}`);
    console.warn(`[OTP FALLBACK LOG] Message: ${text}`);
    console.warn("--------------------------------------------------");
  }
}
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Config ---
const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key-change-this";
const MONGODB_URI =
  process.env.MONGODB_URI ||
  "mongodb+srv://pptkumar_db_user:<db_password>@student-cluster.u2hbhrq.mongodb.net/student-portal?retryWrites=true&w=majority";

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "your_cloud_name",
  api_key: process.env.CLOUDINARY_API_KEY || "your_api_key",
  api_secret: process.env.CLOUDINARY_API_SECRET || "your_api_secret",
});

// Middlewares
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Multer: in-memory (no local files)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB
  fileFilter: (req, file, cb) => {
    const allowed = [
      "application/pdf",
      "image/png",
      "image/jpeg",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.ms-excel",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.ms-powerpoint",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "text/plain",
    ];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error(`Invalid file type: ${file.mimetype}. Allowed: PDF, Images, Word, Excel, PPT, Text.`));
  },
}).array("files", 5);

// --- MongoDB / Mongoose setup ---
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// Schemas
const fileSchema = new mongoose.Schema({
  url: String,
  originalName: String,
  mimetype: String,
  size: Number,
  driveId: String
});

const submissionSchema = new mongoose.Schema(
  {
    studentId: String,
    files: [fileSchema],
    submittedAt: { type: Date, default: Date.now },
    marks: { type: Number, default: null },
    feedback: { type: String, default: null },
    status: { type: String, enum: ["submitted", "graded"], default: "submitted" },
  },
  { _id: true }
);

const userSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  role: { type: String, enum: ["student", "teacher", "ta", "coordinator", "hod", "dean", "admin"], required: true },
  rank: { type: String, default: null }, // Teaching Assistant, Assistant Professor, etc.
  name: { type: String, required: true },
  email: { type: String, default: null },
  rollNumber: { type: String, default: null },
  program: { type: String, enum: ["B.Tech", "BBA"], default: null },
  branch: { type: String, default: null }, // Detailed branch (e.g., AIML - Tigers)
  year: { type: Number, default: null },
  semester: { type: Number, default: null },
  department: { type: String, default: null },
  profilePhotoUrl: { type: String, default: null },
  expertise: { type: String, default: "" },
  passwordHash: { type: String, required: true },
  isApproved: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  otp: { type: String, default: null },
  otpExpires: { type: Date, default: null },
});

const courseSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  name: String,
  code: { type: String, unique: true },
  description: { type: String, default: "" },
  teacherId: String,
  program: { type: String, enum: ["B.Tech", "BBA"] },
  semester: Number,
  sections: [String], // e.g. ["Tigers", "AIDs"] or "AIML - Tigers"
  isMandatory: { type: Boolean, default: false },
  instructorExpertise: { type: String, default: "" },
  examDate: { type: Date, default: null },
  examTime: { type: String, default: null }, // "HH:mm" format
  students: [String],
  materials: [{
    originalName: String,
    url: String,
    fileType: { type: String, enum: ["file", "video"], default: "file" },
    mimetype: String,
    size: Number,
    driveId: String,
    createdAt: { type: Date, default: Date.now }
  }],
  examDateSheets: [{
    id: String,
    name: String,
    type: { type: String, enum: ["file", "generated"], default: "file" },
    url: String, // Drive link for files, JSON string for generated
    content: String, // Or just use url for both
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const assignmentSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  courseId: String,
  title: String,
  description: { type: String, default: "" },
  dueDate: String,
  requiredTime: { type: Number, default: 0 }, // in hours
  maxMarks: Number,
  createdBy: String,
  createdAt: { type: Date, default: Date.now },
  attachments: { type: [fileSchema], default: [] },
  submissions: [submissionSchema],
});

const messageSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  courseId: String, // course.id (for course discussion)
  subjectName: String, // (for common faculty subject discussion)
  userId: String,
  userName: String,
  userRole: String,
  content: String,
  createdAt: { type: Date, default: Date.now },
});

const notificationSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  userId: String,
  message: String,
  type: { type: String, default: "info" }, // info, warning
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

const analyticsEventSchema = new mongoose.Schema({
  eventId: { type: String, unique: true },
  sessionId: { type: String, required: true, index: true },
  userId: { type: String, default: null, index: true },
  eventType: { type: String, required: true, index: true },
  eventData: { type: mongoose.Schema.Types.Mixed, default: {} },
  timestamp: { type: Date, default: Date.now, index: true },
  url: String,
  pathname: String,
  userAgent: String,
  screenResolution: String,
  viewportSize: String,
  timeOnPage: Number,
});

const analyticsSessionSchema = new mongoose.Schema({
  sessionId: { type: String, unique: true, required: true },
  userId: { type: String, default: null },
  startTime: { type: Date, default: Date.now },
  endTime: { type: Date, default: null },
  eventCount: { type: Number, default: 0 },
  userAgent: String,
  lastActivity: { type: Date, default: Date.now },
});

// Models
const User = mongoose.model("User", userSchema);
const Course = mongoose.model("Course", courseSchema);
const Assignment = mongoose.model("Assignment", assignmentSchema);
const Message = mongoose.model("Message", messageSchema);
const Notification = mongoose.model("Notification", notificationSchema);
const AnalyticsEvent = mongoose.model("AnalyticsEvent", analyticsEventSchema);
const AnalyticsSession = mongoose.model("AnalyticsSession", analyticsSessionSchema);

// --- Helpers ---

// Upload a single file buffer to Cloudinary and return meta
async function uploadToCloudinary(file, folder) {
  const base64 = `data:${file.mimetype};base64,${file.buffer.toString(
    "base64"
  )}`;

  const isImage = file.mimetype.startsWith("image/");
  const resourceType = isImage ? "image" : "raw";

  const options = {
    folder: folder || "student-portal",
    resource_type: resourceType,
  };

  if (resourceType === "raw") {
    options.type = "authenticated";
    const ext = path.extname(file.originalname);
    if (ext) {
      options.public_id = uuidv4() + ext;
    }
  }

  const result = await cloudinary.uploader.upload(base64, options);

  return {
    url: result.secure_url,
    originalName: file.originalname,
    mimetype: file.mimetype,
    size: file.size,
  };
}

// --- Google Drive Integration ---
const DRIVE_CLIENT_EMAIL = process.env.GOOGLE_DRIVE_CLIENT_EMAIL;
const DRIVE_PRIVATE_KEY = process.env.GOOGLE_DRIVE_PRIVATE_KEY ? process.env.GOOGLE_DRIVE_PRIVATE_KEY.replace(/\\n/g, "\n").replace(/^"(.*)"$/, "$1") : null;
const DRIVE_FOLDER_ID = process.env.GOOGLE_DRIVE_FOLDER_ID;

if (!DRIVE_CLIENT_EMAIL || !DRIVE_PRIVATE_KEY || !DRIVE_FOLDER_ID) {
  console.warn("⚠️ Google Drive credentials or Folder ID missing in .env");
}

const auth = new google.auth.JWT({
  email: DRIVE_CLIENT_EMAIL,
  key: DRIVE_PRIVATE_KEY,
  scopes: ["https://www.googleapis.com/auth/drive"]
});

const drive = google.drive({ version: "v3", auth });

async function uploadToDrive(file) {
  if (!DRIVE_CLIENT_EMAIL || !DRIVE_PRIVATE_KEY) {
    console.warn("Google Drive credentials not set. Returning mock drive object.");
    return {
      url: "#",
      driveId: "mock-" + uuidv4(),
      originalName: file.originalname,
      mimetype: file.mimetype,
      size: file.size
    };
  }

  try {
    console.log(`[Drive] Starting upload for: ${file.originalname} (${file.size} bytes)`);
    const stream = new PassThrough();
    stream.end(file.buffer);

    const response = await drive.files.create({
      requestBody: {
        name: file.originalname,
        parents: [DRIVE_FOLDER_ID]
      },
      media: {
        mimeType: file.mimetype,
        body: stream
      },
      fields: "id, webViewLink",
      supportsAllDrives: true
    });

    console.log(`[Drive] File created. ID: ${response.data.id}`);

    // Make it readable to anyone with the link (or manage properly per user if needed)
    console.log(`[Drive] Setting permissions for: ${response.data.id}`);
    await drive.permissions.create({
      fileId: response.data.id,
      requestBody: {
        role: "reader",
        type: "anyone"
      },
      supportsAllDrives: true
    });

    console.log(`[Drive] Upload complete for: ${file.originalname}`);

    return {
      url: response.data.webViewLink,
      driveId: response.data.id,
      originalName: file.originalname,
      mimetype: file.mimetype,
      size: file.size
    };
  } catch (err) {
    console.error(`[Drive] Upload error for ${file.originalname}:`, err.message);
    if (err.response) {
      console.error(`[Drive] Error response status: ${err.response.status}`);
      console.error(`[Drive] Error response data:`, JSON.stringify(err.response.data));
    }
    throw err;
  }
}

async function autoEnrollStudents(course) {
  const matchingStudents = await User.find({
    role: "student",
    program: course.program,
    semester: course.semester,
    branch: { $in: course.sections }
  });

  const studentIds = matchingStudents.map(s => s.id);
  course.students = [...new Set([...course.students, ...studentIds])];
  await course.save();
}

// --- Auth middleware ---
function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader)
    return res.status(401).json({ message: "No token" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Invalid token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, role }
    next();
  } catch (err) {
    return res
      .status(401)
      .json({ message: "Token invalid or expired" });
  }
}

// --- Auth routes ---
// Signup: role = 'student' or 'teacher'
app.post("/api/signup", async (req, res) => {
  try {
    const {
      role,
      name,
      email,
      rollNumber,
      program,
      branch,
      year,
      department,
      rank,
      password,
    } = req.body;

    if (!role || !name || !email || !password) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Role-specific checks
    if (role === "student") {
      if (!rollNumber || !program || !branch || !year) {
        return res.status(400).json({ message: "Missing student fields" });
      }
      // Roll number validation: 11 chars and contains "WU"
      if (rollNumber.length !== 11 || !rollNumber.toUpperCase().includes("WU")) {
        return res.status(400).json({ message: "Roll number must be 11 characters and contain 'WU'" });
      }

      const existingStudent = await User.findOne({ rollNumber: rollNumber.toUpperCase() });
      if (existingStudent) {
        return res.status(400).json({ message: "Roll number already exists" });
      }
    } else if (["teacher", "ta", "coordinator", "hod", "dean"].includes(role)) {
      if (role === "teacher") {
        // 1. Verify static Institutional Code instead of dynamic OTP
        const { otp: institutionalCode } = req.body;

        if (!institutionalCode) return res.status(400).json({ message: "Institutional Code required" });
        if (institutionalCode !== "97201") return res.status(400).json({ message: "Invalid Institutional Code" });
      }
    }

    const existingEmail = await User.findOne({ email: email.toLowerCase() });
    if (existingEmail) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    // Derived semester logic
    let derivedSemester = null;
    if (role === "student" && year) {
      // Assuming Sem 1 = Year 1 Sem 1, Sem 2 = Year 1 Sem 2, etc.
      // Since user says semester is derived from year, but there are 2 semesters per year.
      // I'll default to the start semester of that year.
      derivedSemester = (parseInt(year) * 2) - 1;
    }

    const newUser = new User({
      id: uuidv4(),
      role,
      rank: rank || null,
      name,
      email: email.toLowerCase(),
      rollNumber: rollNumber ? rollNumber.toUpperCase() : null,
      program: program || null,
      branch: branch || null,
      year: year ? parseInt(year) : null,
      semester: derivedSemester,
      department: department || null,
      passwordHash,
      isApproved: (role === "student"), // Students approved by default? User said admin approval for teacher.
      createdAt: new Date(),
    });

    await newUser.save();

    const token = jwt.sign({ id: newUser.id, role: newUser.role }, JWT_SECRET, { expiresIn: "7d" });

    res.json({
      token,
      user: {
        id: newUser.id,
        role: newUser.role,
        name: newUser.name,
        email: newUser.email,
        rollNumber: newUser.rollNumber,
        program: newUser.program,
        branch: newUser.branch,
        year: newUser.year,
        semester: newUser.semester,
        department: newUser.department,
      },
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- OTP Endpoints ---

// Request OTP for Signup (Teacher) or General
app.post("/api/auth/send-otp", async (req, res) => {
  const { email, type } = req.body; // type: 'signup' or 'reset'
  if (!email) return res.status(400).json({ message: "Email required" });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 10 * 60 * 1000; // 10 mins

  otpMap.set(email, { code, expires });

  let subject = "Your OTP Code";
  let text = `Your verification code is: ${code}`;
  let to = email;

  if (type === "signup") {
    return res.status(400).json({ message: "Signup OTP is no longer required. Use Institutional Code." });
  }

  await sendEmail(to, subject, text);
  res.json({ message: `OTP sent to ${to}` });
});

// Verify OTP & Reset Password
app.post("/api/auth/reset-password-otp", async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) return res.status(400).json({ message: "All fields required" });

  const record = otpMap.get(email);
  if (!record || Date.now() > record.expires || record.code !== otp) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not found" });

  const hashed = await bcrypt.hash(newPassword, 10);
  user.passwordHash = hashed; // Corrected field name
  await user.save();

  otpMap.delete(email);
  res.json({ message: "Password reset successfully" });
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { role, identifier, password } = req.body;
    if (!role || !identifier || !password) {
      return res.status(400).json({ message: "Missing fields" });
    }

    let user;
    if (role === "student") {
      // Allow login by Roll Number OR Email
      user = await User.findOne({
        role: "student",
        $or: [{ rollNumber: identifier }, { email: identifier }],
      });
    } else if (role === "teacher") {
      user = await User.findOne({
        role: "teacher",
        email: identifier,
      });
    } else {
      return res.status(400).json({ message: "Invalid role" });
    }

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(
      password,
      user.passwordHash
    );
    if (!isMatch) {
      return res
        .status(400)
        .json({ message: "Incorrect password" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.json({
      token,
      user: {
        id: user.id,
        role: user.role,
        name: user.name,
        email: user.email,
        rollNumber: user.rollNumber,
        branch: user.branch,
        year: user.year,
        department: user.department,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- Courses ---
// Get all courses with teacher info
app.get("/api/courses", authMiddleware, async (req, res) => {
  try {
    const courses = await Course.find();
    const result = await Promise.all(courses.map(async (c) => {
      const teacher = await User.findOne({ id: c.teacherId });
      return {
        ...c.toObject(),
        teacherName: teacher ? teacher.name : "Unknown",
        teacherRank: teacher ? teacher.rank : "",
      };
    }));
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get current user profile
app.get("/api/me", authMiddleware, async (req, res) => {
  const user = await User.findOne({ id: req.user.id });
  if (!user)
    return res.status(404).json({ message: "User not found" });

  res.json({
    id: user.id,
    role: user.role,
    name: user.name,
    email: user.email,
    rollNumber: user.rollNumber,
    branch: user.branch,
    year: user.year,
    department: user.department,
    profilePhotoUrl: user.profilePhotoUrl,
  });
});

// Update profile + change password
app.put("/api/me", authMiddleware, async (req, res) => {
  try {
    const {
      name,
      branch,
      year,
      department,
      profilePhotoUrl,
      currentPassword,
      newPassword,
    } = req.body;

    const user = await User.findOne({ id: req.user.id });
    if (!user)
      return res.status(404).json({ message: "User not found" });

    if (name) user.name = name;
    if (user.role === "student") {
      if (branch) user.branch = branch;
      if (year) user.year = year;
    }
    if (user.role === "teacher") {
      if (department) user.department = department;
    }
    if (profilePhotoUrl) {
      // If profilePhotoUrl is a buffer/file from a form, we'd use uploadToCloudinary.
      // But currently script.js sends a URL string.
      // I'll leave it as is for now, but ensure any file uploads for profile use Cloudinary.
      user.profilePhotoUrl = profilePhotoUrl;
    }

    if (currentPassword && newPassword) {
      const isMatch = await bcrypt.compare(
        currentPassword,
        user.passwordHash
      );
      if (!isMatch)
        return res
          .status(400)
          .json({ message: "Current password incorrect" });
      user.passwordHash = await bcrypt.hash(newPassword, 10);
    }

    await user.save();

    res.json({ message: "Profile updated" });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Teacher creates a course
app.post("/api/courses", authMiddleware, async (req, res) => {
  // Teaching assistants cannot create courses
  if (["teacher", "coordinator", "hod", "dean", "admin"].indexOf(req.user.role) === -1) {
    return res.status(403).json({ message: "Only faculty can create courses" });
  }

  const { name, code, description, program, semester, sections, isMandatory } = req.body;
  if (!name || !code || !program || !semester) {
    return res.status(400).json({ message: "Name, code, program, and semester are required" });
  }

  const existing = await Course.findOne({ code });
  if (existing) {
    return res.status(400).json({ message: "Course code already exists" });
  }

  const user = await User.findOne({ id: req.user.id });

  const newCourse = new Course({
    id: uuidv4(),
    name,
    code,
    description: description || "",
    program,
    semester,
    sections: sections || [],
    isMandatory: isMandatory || false,
    instructorExpertise: user?.expertise || "",
    teacherId: req.user.id,
    students: [],
    materials: [],
    examDateSheets: [],
  });

  await newCourse.save();

  // Auto-enroll students based on matching criteria
  await autoEnrollStudents(newCourse);

  res.json(newCourse);
});

// Teacher deletes a course
app.delete("/api/courses/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { reason, confirmCount } = req.body;

  if (["teacher", "coordinator", "hod", "dean", "admin"].indexOf(req.user.role) === -1) {
    return res.status(403).json({ message: "Not authorized" });
  }

  const course = await Course.findOne({ id });
  if (!course) return res.status(404).json({ message: "Course not found" });

  // Only the creator or higher roles (Admin, Dean, HoD) can delete
  const canDelete = course.teacherId === req.user.id || ["admin", "dean", "hod"].includes(req.user.role);
  if (!canDelete) return res.status(403).json({ message: "Unauthorized deletion" });

  if (!reason || reason.split(/\s+/).length < 50) {
    return res.status(400).json({ message: "A minimum 50-word reason is required for deletion" });
  }

  if (confirmCount < 4) {
    return res.status(400).json({ message: "Deletion must be confirmed at least 4 times" });
  }

  await Course.deleteOne({ id });
  res.json({ message: "Course deleted successfully" });
});

// Upload course material (or add video URL)
app.post("/api/courses/:courseId/materials", authMiddleware, (req, res) => {
  if (!["teacher", "ta", "coordinator", "hod"].includes(req.user.role)) {
    return res.status(403).json({ message: "Faculty only" });
  }

  upload(req, res, async (err) => {
    if (err) return res.status(400).json({ message: err.message });
    try {
      const { courseId } = req.params;
      const { videoUrl, originalName } = req.body;
      const course = await Course.findOne({ id: courseId });
      if (!course) return res.status(404).json({ message: "Course not found" });

      if (videoUrl) {
        course.materials.push({
          originalName: originalName || "Video Link",
          url: videoUrl,
          fileType: "video",
          mimetype: "text/url",
          size: 0
        });
      } else {
        const files = req.files || [];
        for (const f of files) {
          // Use Cloudinary instead of Drive to avoid service account quota issues
          const meta = await uploadToCloudinary(f, "student-portal/materials");
          course.materials.push({
            ...meta,
            fileType: "file"
          });
        }
      }

      await course.save();
      res.json({ message: "Materials updated", count: course.materials.length });
    } catch (e) {
      console.error("[Material Upload Error]:", e);
      console.error("Error stack:", e.stack);
      res.status(500).json({ message: e.message || "Server error during upload" });
    }
  });
});

// Delete course material
app.delete("/api/courses/:courseId/materials/:fileId", authMiddleware, async (req, res) => {
  if (req.user.role !== "teacher") {
    return res.status(403).json({ message: "Only teachers can delete materials" });
  }

  const { courseId, fileId } = req.params;
  console.log(`[DELETE] Request to delete material ${fileId} from course ${courseId}`);

  const course = await Course.findOne({ id: courseId });

  if (!course) return res.status(404).json({ message: "Course not found" });
  if (course.teacherId !== req.user.id) {
    return res.status(403).json({ message: "Not authorized" });
  }

  const initialLen = course.materials.length;
  // Debug: Log existing file IDs
  console.log("[DELETE] Existing materials:", course.materials.map(m => ({ id: m._id, name: m.originalName })));

  course.materials = course.materials.filter(m => m._id && m._id.toString() !== fileId);

  if (course.materials.length === initialLen) {
    console.log("[DELETE] File not found (ID mismatch)");
    return res.status(404).json({ message: "File not found" });
  }

  await course.save();
  res.json({ message: "Material deleted" });
});

// Save generated calendar
app.post("/api/courses/:courseId/datesheets/generate", authMiddleware, async (req, res) => {
  if (!["teacher", "coordinator", "hod", "dean"].includes(req.user.role)) {
    return res.status(403).json({ message: "Unauthorized" });
  }
  const { courseId } = req.params;
  const { name, events } = req.body;
  if (!events || events.length === 0) return res.status(400).json({ message: "Events are required" });

  const course = await Course.findOne({ id: courseId });
  if (!course) return res.status(404).json({ message: "Course not found" });

  course.examDateSheets.push({
    id: uuidv4(),
    name: name || "Generated Calendar",
    type: "generated",
    url: JSON.stringify(events), // Store events as stringified JSON in url field
    createdAt: new Date()
  });

  await course.save();
  res.json({ message: "Calendar saved" });
});
// --- Date Sheets / Exam Schedule ---
// Update Course (for Exam Schedule)
app.put("/api/courses/:courseId", authMiddleware, async (req, res) => {
  if (req.user.role !== "teacher") return res.status(403).json({ message: "Only teachers can update courses" });

  const { courseId } = req.params;
  const { examDate, examTime } = req.body; // Can extend to other fields

  try {
    const course = await Course.findOne({ id: courseId });
    if (!course) return res.status(404).json({ message: "Course not found" });
    if (course.teacherId !== req.user.id) return res.status(403).json({ message: "Not your course" });

    if (examDate !== undefined) course.examDate = examDate;
    if (examTime !== undefined) course.examTime = examTime;

    await course.save();
    res.json(course);
  } catch (err) {
    res.status(500).json({ message: "Update error" });
  }
});

// Get aggregated exam schedule for student
app.get("/api/student/exam-schedule", authMiddleware, async (req, res) => {
  if (req.user.role !== "student") return res.status(403).json({ message: "Student only" });

  try {
    const myCourses = await Course.find({ students: req.user.id });
    const schedule = myCourses
      .filter(c => c.examDate)
      .map(c => ({
        courseName: c.name,
        courseCode: c.code,
        examDate: c.examDate,
        examTime: c.examTime
      }))
      .sort((a, b) => new Date(a.examDate) - new Date(b.examDate));

    res.json(schedule);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Teacher uploads date sheet (Legacy/Alternative)
app.post("/api/courses/:courseId/datesheets", authMiddleware, (req, res) => {
  if (req.user.role !== "teacher") return res.status(403).json({ message: "Only teachers can upload date sheets" });

  upload(req, res, async (err) => {
    if (err) return res.status(400).json({ message: err.message });
    try {
      const { courseId } = req.params;
      const course = await Course.findOne({ id: courseId });
      if (!course) return res.status(404).json({ message: "Course not found" });
      if (course.teacherId !== req.user.id) return res.status(403).json({ message: "Not authorized" });

      const files = req.files || [];
      if (!course.examDateSheets) course.examDateSheets = []; // Safety init

      for (const f of files) {
        const meta = await uploadToDrive(f);
        course.examDateSheets.push({
          ...meta,
          id: meta.driveId,
          type: "file"
        });
      }
      await course.save();
      res.json({ message: "Date sheets uploaded" });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  });
});

// Get Date Sheets
app.get("/api/courses/:courseId/datesheets", authMiddleware, async (req, res) => {
  const { courseId } = req.params;
  const course = await Course.findOne({ id: courseId });
  if (!course) return res.status(404).json({ message: "Course not found" });
  res.json(course.examDateSheets || []);
});

// Delete Date Sheet
app.delete("/api/courses/:courseId/datesheets/:fileId", authMiddleware, async (req, res) => {
  if (req.user.role !== "teacher") return res.status(403).json({ message: "Teacher only" });

  const { courseId, fileId } = req.params;
  const course = await Course.findOne({ id: courseId });
  if (!course) return res.status(404).json({ message: "Course not found" });
  if (course.teacherId !== req.user.id) return res.status(403).json({ message: "Not authorized" });

  const initialLen = course.examDateSheets.length;
  course.examDateSheets = course.examDateSheets.filter(f =>
    (f.id !== fileId) && (!f._id || f._id.toString() !== fileId)
  );

  if (course.examDateSheets.length === initialLen) return res.status(404).json({ message: "File not found" });

  await course.save();
  res.json({ message: "Deleted" });
});

// Student joins a course
app.post(
  "/api/courses/:courseId/join",
  authMiddleware,
  async (req, res) => {
    if (req.user.role !== "student") {
      return res.status(403).json({
        message: "Only students can join courses",
      });
    }

    const { courseId } = req.params;
    const course = await Course.findOne({ id: courseId });
    if (!course)
      return res
        .status(404)
        .json({ message: "Course not found" });

    if (!course.students.includes(req.user.id)) {
      course.students.push(req.user.id);
      await course.save();
    }

    res.json({ message: "Joined course", course });
  }
);

// Get courses of current user
app.get("/api/my-courses", authMiddleware, async (req, res) => {
  let courses;
  if (req.user.role === "student") {
    courses = await Course.find({
      students: req.user.id,
    });
  } else if (req.user.role === "teacher") {
    courses = await Course.find({ teacherId: req.user.id });
  } else {
    return res.status(400).json({ message: "Unknown role" });
  }

  const teacherIds = [
    ...new Set(courses.map((c) => c.teacherId).filter(Boolean)),
  ];
  const teachers = await User.find({ id: { $in: teacherIds } });
  const teacherMap = new Map(
    teachers.map((t) => [t.id, t.name])
  );

  const result = courses.map((c) => ({
    ...c.toObject(),
    teacherName: c.teacherId ? teacherMap.get(c.teacherId) : null,
    studentCount: c.students.length,
  }));

  res.json(result);
});

// Dashboard summary
app.get("/api/dashboard/summary", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    const myCourses = await Course.find(
      userRole === "student" ? { students: userId } : { teacherId: userId }
    );
    const myCoursesCount = myCourses.length;

    if (userRole === "student") {
      const courseIds = myCourses.map((c) => c.id);
      const assignments = await Assignment.find({ courseId: { $in: courseIds } });
      const pendingCount = assignments.filter((a) => {
        const sub = a.submissions.find((s) => s.studentId === userId);
        return !sub;
      }).length;

      res.json({
        myCoursesCount,
        pendingAssignmentsCount: pendingCount,
      });
    } else {
      // Teacher grading summary
      const assignments = await Assignment.find({ createdBy: userId });
      let totalToGrade = 0;
      assignments.forEach(a => {
        const unmanagedCount = a.submissions.filter(s => s.status !== "graded").length;
        totalToGrade += unmanagedCount;
      });

      res.json({
        myCoursesCount,
        submissionsToGradeCount: totalToGrade,
      });
    }
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Common Subject Discussion Board for Teachers
app.get("/api/faculty/discussion/:subjectName", authMiddleware, async (req, res) => {
  if (!["teacher", "ta", "coordinator", "hod", "dean"].includes(req.user.role)) {
    return res.status(403).json({ message: "Faculty only" });
  }
  const { subjectName } = req.params;
  const messages = await Message.find({ subjectName }).sort({ createdAt: -1 });
  res.json(messages);
});

app.post("/api/faculty/discussion/:subjectName", authMiddleware, async (req, res) => {
  if (!["teacher", "ta", "coordinator", "hod", "dean"].includes(req.user.role)) {
    return res.status(403).json({ message: "Faculty only" });
  }
  const { subjectName } = req.params;
  const { content } = req.body;
  const user = await User.findOne({ id: req.user.id });

  const newMessage = new Message({
    id: uuidv4(),
    subjectName,
    userId: req.user.id,
    userName: user.name,
    userRole: user.role,
    content,
  });

  await newMessage.save();
  res.json(newMessage);
});
// Get notifications for a student
app.get("/api/notifications", authMiddleware, async (req, res) => {
  if (req.user.role !== "student") return res.json([]);

  const studentId = req.user.id;
  const now = new Date();

  try {
    // 1. Regenerate urgent notifications based on assignments
    const myCourses = await Course.find({ students: studentId });
    const courseIds = myCourses.map(c => c.id);
    const assignments = await Assignment.find({ courseId: { $in: courseIds } });

    for (const a of assignments) {
      const isSubmitted = a.submissions.some(s => s.studentId === studentId);
      if (isSubmitted) continue;

      const due = new Date(a.dueDate);
      const timeLeft = due - now;
      const requiredMs = (a.requiredTime || 0) * 3600000;

      // Condition: Notification turns red (urgent) if remaining time is twice the required time or less
      if (timeLeft > 0 && timeLeft <= 2 * requiredMs) {
        const msg = `URGENT: Assignment "${a.title}" requires ~${a.requiredTime}h. You have less than ${Math.round(timeLeft / 3600000)}h left!`;
        const exists = await Notification.findOne({ userId: studentId, message: msg });
        if (!exists) {
          await Notification.create({
            id: uuidv4(),
            userId: studentId,
            message: msg,
            type: "warning",
            createdAt: now
          });
        }
      }
    }

    const notifs = await Notification.find({ userId: studentId }).sort({ createdAt: -1 });
    res.json(notifs);
  } catch (err) {
    console.error("Notifications error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- Assignments ---
// Teacher creates assignment (Multipart for attachments)
app.post("/api/assignments", authMiddleware, (req, res) => {
  if (req.user.role !== "teacher") {
    return res
      .status(403)
      .json({ message: "Only teachers can create assignments" });
  }

  upload(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ message: err.message || "Upload error" });
    }

    try {
      const { courseId, title, description, dueDate, maxMarks, requiredTime } = req.body;
      if (!courseId || !title || !dueDate || !maxMarks) {
        return res.status(400).json({ message: "Missing fields" });
      }

      const course = await Course.findOne({ id: courseId });
      if (!course)
        return res.status(404).json({ message: "Course not found" });
      if (course.teacherId !== req.user.id) {
        return res.status(403).json({ message: "Not authorized" });
      }

      const newFiles = [];
      const files = req.files || [];
      for (const f of files) {
        const meta = await uploadToDrive(f);
        newFiles.push(meta);
      }

      const newAssignment = new Assignment({
        id: uuidv4(),
        courseId,
        title,
        description: description || "",
        dueDate,
        requiredTime: parseInt(requiredTime) || 0,
        maxMarks: parseInt(maxMarks),
        createdBy: req.user.id,
        createdAt: new Date(),
        attachments: newFiles,
        submissions: [],
      });

      await newAssignment.save();
      res.json(newAssignment);

    } catch (e) {
      console.error("Create Assignment Error:", e);
      res.status(500).json({ message: "Server error" });
    }
  });
});

// Get assignments for a course
app.get(
  "/api/courses/:courseId/assignments",
  authMiddleware,
  async (req, res) => {
    try {
      const { courseId } = req.params;
      const course = await Course.findOne({ id: courseId });
      if (!course) return res.status(404).json({ message: "Course not found" });

      if (req.user.role === "student") {
        const student = await User.findOne({ id: req.user.id });
        const isMatched = course.sections.includes(student.branch) && course.program === student.program;

        if (!isMatched && !["admin", "dean"].includes(req.user.role)) {
          // Optionally joined students cannot see assignments
          return res.json([]);
        }
      }

      const assignments = await Assignment.find({ courseId });
      res.json(assignments);
    } catch (e) {
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Student submits assignment (multiple files)
app.post(
  "/api/assignments/:assignmentId/submit",
  authMiddleware,
  (req, res) => {
    if (req.user.role !== "student") {
      return res.status(403).json({
        message: "Only students can submit assignments",
      });
    }

    upload(req, res, async (err) => {
      if (err) {
        console.error("Upload error:", err);
        return res.status(400).json({
          message: err.message || "Upload error",
        });
      }

      try {
        const { assignmentId } = req.params;
        const assignment = await Assignment.findOne({
          id: assignmentId,
        });
        if (!assignment) {
          return res
            .status(404)
            .json({ message: "Assignment not found" });
        }

        const course = await Course.findOne({
          id: assignment.courseId,
        });
        if (
          !course ||
          !course.students.includes(req.user.id)
        ) {
          return res.status(403).json({
            message: "You are not enrolled in this course",
          });
        }

        const uploadedFiles = [];
        for (const file of req.files || []) {
          const meta = await uploadToDrive(file);
          uploadedFiles.push(meta);
        }

        let submission =
          assignment.submissions.find(
            (s) => s.studentId === req.user.id
          ) || null;

        if (!submission) {
          submission = {
            studentId: req.user.id,
            files: uploadedFiles,
            submittedAt: new Date(),
            marks: null,
            feedback: null,
          };
          assignment.submissions.push(submission);
        } else {
          submission.files.push(...uploadedFiles);
          submission.submittedAt = new Date();
        }

        await assignment.save();
        res.json({ message: "Submitted", submission });
      } catch (e) {
        console.error("Submit error:", e);
        res.status(500).json({ message: "Server error" });
      }
    });
  }
);

// Delete submission file (Student specific, 5 min limit)
app.delete("/api/assignments/:assignmentId/submission/files/:fileId", authMiddleware, async (req, res) => {
  if (req.user.role !== "student") return res.status(403).json({ message: "Only students action" });

  try {
    const { assignmentId, fileId } = req.params;
    const assignment = await Assignment.findOne({ id: assignmentId });
    if (!assignment) return res.status(404).json({ message: "Assignment not found" });

    const submission = assignment.submissions.find(s => s.studentId === req.user.id);
    if (!submission) return res.status(404).json({ message: "Submission not found" });

    // Check time limit (5 mins)
    const now = new Date();
    const diffMs = now - new Date(submission.submittedAt);
    const diffMins = diffMs / (1000 * 60);

    if (diffMins > 5) {
      return res.status(400).json({ message: "Time limit exceeded. You can only delete files within 5 minutes of submission." });
    }

    const initialLen = submission.files.length;
    submission.files = submission.files.filter(f => f._id.toString() !== fileId);

    if (submission.files.length === initialLen) {
      return res.status(404).json({ message: "File not found" });
    }

    await assignment.save();
    res.json({ message: "File deleted", files: submission.files });
  } catch (err) {
    console.error("Delete file error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Teacher views submissions for an assignment
app.get(
  "/api/assignments/:assignmentId/submissions",
  authMiddleware,
  async (req, res) => {
    if (req.user.role !== "teacher") {
      return res.status(403).json({
        message: "Only teachers can view submissions",
      });
    }

    const { assignmentId } = req.params;
    const assignment = await Assignment.findOne({
      id: assignmentId,
    });
    if (!assignment)
      return res.status(404).json({
        message: "Assignment not found",
      });

    const course = await Course.findOne({
      id: assignment.courseId,
    });
    if (!course || course.teacherId !== req.user.id) {
      return res.status(403).json({
        message: "You are not teacher of this course",
      });
    }

    const studentIds = assignment.submissions.map(
      (s) => s.studentId
    );
    const students = await User.find({ id: { $in: studentIds } });
    const studentMap = new Map(
      students.map((s) => [s.id, s])
    );

    const result = assignment.submissions.map((s) => {
      const student = studentMap.get(s.studentId);
      return {
        studentId: s.studentId,
        studentName: student ? student.name : "Unknown",
        rollNumber: student ? student.rollNumber : null,
        files: s.files,
        submittedAt: s.submittedAt,
        marks: s.marks,
        feedback: s.feedback,
      };
    });

    res.json({ assignmentId, submissions: result });
  }
);

// Teacher grades a submission
app.post(
  "/api/assignments/:assignmentId/grade",
  authMiddleware,
  async (req, res) => {
    if (req.user.role !== "teacher") {
      return res.status(403).json({
        message: "Only teachers can grade",
      });
    }

    const { assignmentId } = req.params;
    const { studentId, marks, feedback } = req.body;

    const assignment = await Assignment.findOne({
      id: assignmentId,
    });
    if (!assignment)
      return res.status(404).json({
        message: "Assignment not found",
      });

    const course = await Course.findOne({
      id: assignment.courseId,
    });
    if (!course || course.teacherId !== req.user.id) {
      return res.status(403).json({
        message: "You are not teacher of this course",
      });
    }

    const submission = assignment.submissions.find(
      (s) => s.studentId === studentId
    );
    if (!submission)
      return res.status(404).json({
        message: "Submission not found",
      });

    submission.marks = marks;
    if (feedback) submission.feedback = feedback;

    await assignment.save();

    res.json({ message: "Graded", submission });
  }
);

// --- Course messages (discussion board) ---
// Get messages for a course
app.get(
  "/api/courses/:courseId/messages",
  authMiddleware,
  async (req, res) => {
    const { courseId } = req.params;
    const course = await Course.findOne({ id: courseId });
    if (!course) return res.status(404).json({ message: "Course not found" });

    // Check enrollment? Usually yes, but maybe readable if public? Strict for now.
    if (req.user.role === "student" && !course.students.includes(req.user.id)) {
      return res.status(403).json({ message: "Not enrolled" });
    }

    // Optimize: Join with User to get names
    // We can do a manual join or aggregation
    const messages = await Message.find({ courseId }).sort({ createdAt: -1 }); // Newest First

    // Populate user info
    // Fetch all userIds
    const userIds = [...new Set(messages.map(m => m.userId))];
    const users = await User.find({ id: { $in: userIds } });
    const userMap = new Map(users.map(u => [u.id, u]));

    const result = messages.map(m => {
      const u = userMap.get(m.userId);
      return {
        id: m.id,
        content: m.content,
        createdAt: m.createdAt,
        userId: m.userId,
        userName: u ? u.name : "Unknown",
        userRole: u ? u.role : "?"
      };
    });

    res.json(result);
  }
);

// Post a message in a course
app.post(
  "/api/courses/:courseId/messages",
  authMiddleware,
  async (req, res) => {
    const { courseId } = req.params;
    const { content } = req.body;
    if (!content)
      return res
        .status(400)
        .json({ message: "Content required" });

    const course = await Course.findOne({ id: courseId });
    if (!course)
      return res
        .status(404)
        .json({ message: "Course not found" });

    if (
      req.user.role === "student" &&
      !course.students.includes(req.user.id)
    ) {
      return res.status(403).json({
        message: "You are not enrolled in this course",
      });
    }
    if (
      req.user.role === "teacher" &&
      course.teacherId !== req.user.id
    ) {
      return res.status(403).json({
        message: "You are not teacher of this course",
      });
    }

    const newMessage = new Message({
      id: uuidv4(),
      courseId,
      userId: req.user.id,
      content,
      createdAt: new Date(),
    });

    await newMessage.save();
    res.json(newMessage);
  }
);

// --- Study materials upload ---
app.post(
  "/api/courses/:courseId/materials",
  authMiddleware,
  (req, res) => {
    if (req.user.role !== "teacher") {
      return res.status(403).json({
        message: "Only teachers can upload materials",
      });
    }

    console.log(`[Materials] Upload request received for Course: ${req.params.courseId} from User: ${req.user.id}`);

    upload(req, res, async (err) => {
      if (err) {
        console.error("Upload error:", err);
        return res.status(400).json({
          message: err.message || "Upload error",
        });
      }

      try {
        const { courseId } = req.params;
        const course = await Course.findOne({ id: courseId });
        if (!course)
          return res.status(404).json({
            message: "Course not found",
          });

        if (course.teacherId !== req.user.id) {
          return res.status(403).json({
            message:
              "You are not the teacher of this course",
          });
        }

        const uploadedFiles = [];
        for (const file of req.files || []) {
          const meta = await uploadToDrive(file);
          uploadedFiles.push(meta);
          course.materials.push({
            ...meta,
            fileType: "file"
          });
        }

        await course.save();

        res.json({
          message: "Material uploaded",
          files: uploadedFiles,
        });
      } catch (e) {
        console.error("Material upload error:", e);
        res.status(500).json({ message: "Server error" });
      }
    });
  }
);

// --- Dashboard summary ---
app.get(
  "/api/dashboard/summary",
  authMiddleware,
  async (req, res) => {
    if (req.user.role === "student") {
      const myCourses = await Course.find({
        students: req.user.id,
      });
      const courseIds = myCourses.map((c) => c.id);

      const myAssignments = await Assignment.find({
        courseId: { $in: courseIds },
      });

      const now = new Date();
      const pendingAssignments = myAssignments.filter(
        (a) => {
          const submission = a.submissions.find(
            (s) => s.studentId === req.user.id
          );
          const due = new Date(a.dueDate);
          return !submission && due >= now;
        }
      );

      const recentMessages = await Message.find({
        courseId: { $in: courseIds },
      })
        .sort({ createdAt: -1 })
        .limit(5);

      res.json({
        myCoursesCount: myCourses.length,
        pendingAssignmentsCount: pendingAssignments.length,
        pendingAssignments,
        recentMessages,
      });
    } else if (req.user.role === "teacher") {
      const myCourses = await Course.find({
        teacherId: req.user.id,
      });
      const courseIds = myCourses.map((c) => c.id);

      const myAssignments = await Assignment.find({
        courseId: { $in: courseIds },
      });

      let submissionsToGrade = [];
      myAssignments.forEach((a) => {
        a.submissions.forEach((s) => {
          if (s.marks === null || s.marks === undefined) {
            submissionsToGrade.push({
              assignmentId: a.id,
              courseId: a.courseId,
              studentId: s.studentId,
              submittedAt: s.submittedAt,
            });
          }
        });
      });

      res.json({
        myCoursesCount: myCourses.length,
        assignmentsCount: myAssignments.length,
        submissionsToGradeCount:
          submissionsToGrade.length,
      });
    } else {
      res.status(400).json({ message: "Unknown role" });
    }
  }
);

// --- Health Check ---
app.get("/health", (req, res) => {
  const healthcheck = {
    uptime: process.uptime(),
    message: "OK",
    timestamp: Date.now(),
    mongoDBStatus: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected"
  };
  try {
    res.status(200).json(healthcheck);
  } catch (error) {
    healthcheck.message = error;
    res.status(503).json(healthcheck);
  }
});

// --- Analytics Endpoints ---
// Store analytics events
app.post("/api/analytics/events", async (req, res) => {
  try {
    const { sessionId, userId, events } = req.body;

    if (!sessionId || !events || !Array.isArray(events)) {
      return res.status(400).json({ message: "Invalid request" });
    }

    // Create or update session
    let session = await AnalyticsSession.findOne({ sessionId });
    if (!session) {
      session = new AnalyticsSession({
        sessionId,
        userId: userId || null,
        startTime: new Date(),
        userAgent: events[0]?.userAgent || null,
        eventCount: 0,
      });
    }

    // Store events
    const savedEvents = [];
    for (const event of events) {
      try {
        const analyticsEvent = new AnalyticsEvent({
          ...event,
          sessionId,
          userId: userId || event.userId || null,
        });
        await analyticsEvent.save();
        savedEvents.push(analyticsEvent);
        session.eventCount += 1;
      } catch (err) {
        // Skip duplicate events (eventId unique constraint)
        if (err.code !== 11000) {
          console.error("Error saving event:", err);
        }
      }
    }

    session.lastActivity = new Date();
    await session.save();

    res.json({
      message: "Events stored",
      count: savedEvents.length,
      sessionId,
    });
  } catch (err) {
    console.error("Analytics events error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get session data
app.get("/api/analytics/sessions/:sessionId", async (req, res) => {
  try {
    const { sessionId } = req.params;

    const session = await AnalyticsSession.findOne({ sessionId });
    if (!session) {
      return res.status(404).json({ message: "Session not found" });
    }

    const events = await AnalyticsEvent.find({ sessionId }).sort({ timestamp: 1 });

    res.json({
      session,
      events,
      eventCount: events.length,
    });
  } catch (err) {
    console.error("Get session error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all sessions
app.get("/api/analytics/sessions", async (req, res) => {
  try {
    const { userId, startDate, endDate, limit = 100 } = req.query;

    const query = {};
    if (userId) query.userId = userId;
    if (startDate || endDate) {
      query.startTime = {};
      if (startDate) query.startTime.$gte = new Date(startDate);
      if (endDate) query.startTime.$lte = new Date(endDate);
    }

    const sessions = await AnalyticsSession.find(query)
      .sort({ startTime: -1 })
      .limit(parseInt(limit));

    res.json(sessions);
  } catch (err) {
    console.error("Get sessions error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get analytics summary
app.get("/api/analytics/summary", async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    const dateFilter = {};
    if (startDate || endDate) {
      dateFilter.timestamp = {};
      if (startDate) dateFilter.timestamp.$gte = new Date(startDate);
      if (endDate) dateFilter.timestamp.$lte = new Date(endDate);
    }

    const totalEvents = await AnalyticsEvent.countDocuments(dateFilter);
    const totalSessions = await AnalyticsSession.countDocuments(
      startDate || endDate ? { startTime: dateFilter.timestamp } : {}
    );
    const uniqueUsers = await AnalyticsEvent.distinct("userId", dateFilter);

    // Calculate average session duration (for completed sessions)
    const avgDurationResult = await AnalyticsSession.aggregate([
      {
        $match: {
          endTime: { $ne: null },
          ...(startDate || endDate ? { startTime: dateFilter.timestamp } : {})
        }
      },
      {
        $group: {
          _id: null,
          avgDuration: { $avg: { $subtract: ["$endTime", "$startTime"] } }
        }
      }
    ]);

    const avgSessionDurationMs = avgDurationResult.length > 0 ? avgDurationResult[0].avgDuration : 0;
    const avgSessionDurationMin = Math.round(avgSessionDurationMs / 60000);

    // Event type breakdown
    const eventTypes = await AnalyticsEvent.aggregate([
      { $match: dateFilter },
      { $group: { _id: "$eventType", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    // Page views
    const pageViews = await AnalyticsEvent.aggregate([
      { $match: { ...dateFilter, eventType: "page_view" } },
      { $group: { _id: "$pathname", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    // Most clicked buttons
    const buttonClicks = await AnalyticsEvent.aggregate([
      { $match: { ...dateFilter, eventType: "button_click" } },
      { $group: { _id: "$eventData.buttonText", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]);

    res.json({
      summary: {
        totalEvents,
        totalSessions,
        uniqueUsers: uniqueUsers.length,
        avgSessionDuration: avgSessionDurationMin + "m",
      },
      eventTypes,
      pageViews,
      buttonClicks,
    });
  } catch (err) {
    console.error("Analytics summary error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Export analytics data
app.get("/api/analytics/export", async (req, res) => {
  try {
    const { format = "json", sessionId, startDate, endDate } = req.query;

    const query = {};
    if (sessionId) query.sessionId = sessionId;
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = new Date(startDate);
      if (endDate) query.timestamp.$lte = new Date(endDate);
    }

    const events = await AnalyticsEvent.find(query).sort({ timestamp: 1 }).lean();

    if (format === "csv") {
      // Convert to CSV
      const csv = convertToCSV(events);
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=analytics_export.csv");
      res.send(csv);
    } else {
      // JSON format
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", "attachment; filename=analytics_export.json");
      res.json(events);
    }
  } catch (err) {
    console.error("Export error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Helper function to convert events to CSV
function convertToCSV(events) {
  if (events.length === 0) return "";

  const headers = ["eventId", "sessionId", "userId", "eventType", "timestamp", "url", "pathname"];
  const rows = events.map(event =>
    headers.map(header => {
      const value = event[header] || "";
      return typeof value === "string" && value.includes(",") ? `"${value}"` : value;
    }).join(",")
  );


  return [headers.join(","), ...rows].join("\n");
}

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

