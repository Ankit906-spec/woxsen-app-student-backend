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

dotenv.config();

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
    ];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error("Invalid file type"));
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
const userSchema = new mongoose.Schema({
  id: { type: String, unique: true }, // for JWT + consistency
  role: { type: String, enum: ["student", "teacher"], required: true },
  name: { type: String, required: true },
  email: { type: String, default: null }, // Required for teacher, optional->required for student now
  rollNumber: { type: String, default: null },
  branch: { type: String, default: null },
  year: { type: String, default: null },
  department: { type: String, default: null },
  profilePhotoUrl: { type: String, default: null },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  otp: { type: String, default: null },
  otpExpires: { type: Date, default: null },
});

const fileSchema = new mongoose.Schema(
  {
    url: String,
    originalName: String,
    mimetype: String,
    size: Number,
  }
);

const submissionSchema = new mongoose.Schema(
  {
    studentId: String,
    files: [fileSchema],
    submittedAt: Date,
    marks: { type: Number, default: null },
    feedback: { type: String, default: null },
  },
  { _id: false }
);

const courseSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  name: String,
  code: { type: String, unique: true },
  description: { type: String, default: "" },
  teacherId: String, // user.id
  students: [String], // array of user.id (students)
  materials: [fileSchema], // study materials
  examDateSheets: [fileSchema], // exam date sheets
});

const assignmentSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  courseId: String, // course.id
  title: String,
  description: { type: String, default: "" },
  dueDate: String,
  maxMarks: Number,
  createdBy: String, // teacher user.id
  createdAt: { type: Date, default: Date.now },
  attachments: { type: [fileSchema], default: [] },
  submissions: [submissionSchema],
});

const messageSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  courseId: String,
  userId: String,
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

// Models
const User = mongoose.model("User", userSchema);
const Course = mongoose.model("Course", courseSchema);
const Assignment = mongoose.model("Assignment", assignmentSchema);
const Message = mongoose.model("Message", messageSchema);
const Notification = mongoose.model("Notification", notificationSchema);

// --- Helpers ---

// Upload a single file buffer to Cloudinary and return meta
async function uploadToCloudinary(file, folder) {
  const base64 = `data:${file.mimetype};base64,${file.buffer.toString(
    "base64"
  )}`;

  // Use "raw" for non-image files to avoid "authenticated" delivery issues with PDFs
  const isImage = file.mimetype.startsWith("image/");
  const resourceType = isImage ? "image" : "raw";

  const options = {
    folder: folder || "student-portal",
    resource_type: resourceType,
  };

  if (resourceType === "raw") {
    // Authenticated for raw files to ensure secure delivery
    options.type = "authenticated";
    // Preserve extension
    const ext = path.extname(file.originalname);
    if (ext) {
      options.public_id = uuidv4() + ext;
    }
  }

  const result = await cloudinary.uploader.upload(base64, options);

  // Cloudinary returns a signed secure_url automatically if type is 'authenticated'
  // using this is safer than manual construction.
  console.log("Uploaded File:", result.secure_url);

  return {
    url: result.secure_url,
    originalName: file.originalname,
    mimetype: file.mimetype,
    size: file.size,
  };
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
      branch,
      year,
      department,
      password,
    } = req.body;
    if (!role || !name || !email || !password) {
      return res
        .status(400)
        .json({ message: "Missing required fields (Name, Email, Password)" });
    }

    // Role-specific checks
    if (role === "student") {
      if (!rollNumber || !branch || !year) {
        return res.status(400).json({
          message:
            "Student must have rollNumber, branch and year",
        });
      }
      const existingStudent = await User.findOne({
        role: "student",
        rollNumber,
      });
      if (existingStudent) {
        return res.status(400).json({
          message: "Student with this roll number already exists",
        });
      }
    } else if (role === "teacher") {
      if (!department) {
        return res.status(400).json({
          message: "Teacher must have department",
        });
      }
    } else {
      return res.status(400).json({ message: "Invalid role" });
    }

    // Check email uniqueness global or per role? Let's do per role or global. 
    // Usually email is unique globally. Let's check generally.
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({
      id: uuidv4(),
      role,
      name,
      email: email,
      rollNumber: rollNumber || null,
      branch: branch || null,
      year: year || null,
      department: department || null,
      profilePhotoUrl: null,
      passwordHash,
      createdAt: new Date(),
    });

    await newUser.save();

    const token = jwt.sign(
      { id: newUser.id, role: newUser.role },
      JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.json({
      token,
      user: {
        id: newUser.id,
        role: newUser.role,
        name: newUser.name,
        email: newUser.email,
        rollNumber: newUser.rollNumber,
        branch: newUser.branch,
        year: newUser.year,
        department: newUser.department,
      },
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login: student => rollNumber OR email, teacher => email
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

// --- Forgot Password ---
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Generate 6 digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

    await user.save();

    // MOCK EMAIL SENDING
    console.log(`\n=== EMAIL MOCK ===`);
    console.log(`To: ${email}`);
    console.log(`Subject: Password Reset OTP`);
    console.log(`Your OTP is: ${otp}`);
    console.log(`==================\n`);

    res.json({ message: "OTP sent to email (check server console)" });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- Reset Password ---
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const user = await User.findOne({ email, otp });
    if (!user) {
      return res.status(400).json({ message: "Invalid OTP or Email" });
    }

    if (user.otpExpires < new Date()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = passwordHash;
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.json({ message: "Password reset successful. Please login." });
  } catch (err) {
    console.error("Reset password error:", err);
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
    if (profilePhotoUrl) user.profilePhotoUrl = profilePhotoUrl;

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

// --- Courses ---
// Get all courses (search optional)
app.get("/api/courses", authMiddleware, async (req, res) => {
  const q = (req.query.q || "").toLowerCase();

  let courses = await Course.find({});
  if (q) {
    courses = courses.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.code.toLowerCase().includes(q) ||
        (c.description &&
          c.description.toLowerCase().includes(q))
    );
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
  }));

  res.json(result);
});

// Teacher creates a course
app.post("/api/courses", authMiddleware, async (req, res) => {
  if (req.user.role !== "teacher") {
    return res
      .status(403)
      .json({ message: "Only teachers can create courses" });
  }

  const { name, code, description } = req.body;
  if (!name || !code) {
    return res
      .status(400)
      .json({ message: "Name and code are required" });
  }

  const existing = await Course.findOne({ code });
  if (existing) {
    return res
      .status(400)
      .json({ message: "Course code already exists" });
  }

  const newCourse = new Course({
    id: uuidv4(),
    name,
    code,
    description: description || "",
    teacherId: req.user.id,
    students: [],
    materials: [],
    examDateSheets: [],
  });

  await newCourse.save();
  res.json(newCourse);
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

// --- Date Sheets ---
// Upload Date Sheet
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
        const meta = await uploadToCloudinary(f, "datesheets");
        course.examDateSheets.push(meta);
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
  course.examDateSheets = course.examDateSheets.filter(f => f._id && f._id.toString() !== fileId);

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

// --- Notifications ---
// Get (and generate) notifications for a student
app.get("/api/notifications", authMiddleware, async (req, res) => {
  if (req.user.role !== "student") {
    return res.json([]);
  }

  const studentId = req.user.id;
  const now = new Date();
  const warningTime = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24h from now

  try {
    // 1. LAZY GENERATION: Check for pending assignments due soon (< 24h)
    const myCourses = await Course.find({ students: studentId });
    const courseIds = myCourses.map(c => c.id);
    const assignments = await Assignment.find({ courseId: { $in: courseIds } });

    for (const a of assignments) {
      // Check if submitted
      const isSubmitted = a.submissions.some(s => s.studentId === studentId);
      if (!isSubmitted) {
        const due = new Date(a.dueDate);
        // Requirement: "send notification for the deadline"
        // Condition: Due in future < 24h OR Due in past (Overdue)
        if (due > now && due < warningTime) {
          const msg = `Reminder: Assignment "${a.title}" is due in less than 24 hours.`;
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
        } else if (due < now) {
          const msg = `Overdue: Assignment "${a.title}" was due on ${due.toLocaleDateString()}.`;
          const exists = await Notification.findOne({ userId: studentId, message: msg });
          // Only notify if not already notified? Or notify once? 
          // Simple dedupe prevents spam on every refresh.
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
    }

    // 2. Return all notifications
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
      const { courseId, title, description, dueDate, maxMarks } = req.body;
      if (!courseId || !title || !dueDate || !maxMarks) {
        return res.status(400).json({ message: "Missing fields" });
      }

      const course = await Course.findOne({ id: courseId });
      if (!course)
        return res.status(404).json({ message: "Course not found" });
      if (course.teacherId !== req.user.id) {
        return res.status(403).json({
          message: "You are not the teacher of this course",
        });
      }

      const attachments = [];
      if (req.files && req.files.length > 0) {
        for (const file of req.files) {
          const meta = await uploadToCloudinary(file, "attachments");
          attachments.push(meta);
        }
      }

      const newAssignment = new Assignment({
        id: uuidv4(),
        courseId,
        title,
        description: description || "",
        dueDate,
        maxMarks,
        createdBy: req.user.id,
        createdAt: new Date(),
        attachments: attachments, // Using the new field
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
    const { courseId } = req.params;
    const assignments = await Assignment.find({ courseId });
    res.json(assignments);
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
          const meta = await uploadToCloudinary(
            file,
            "assignments"
          );
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
    const messages = await Message.find({ courseId }).sort({
      createdAt: 1,
    });

    const userIds = [
      ...new Set(messages.map((m) => m.userId)),
    ];
    const users = await User.find({ id: { $in: userIds } });
    const userMap = new Map(
      users.map((u) => [u.id, u])
    );

    const result = messages.map((m) => {
      const user = userMap.get(m.userId);
      return {
        ...m.toObject(),
        userName: user ? user.name : "Unknown",
        userRole: user ? user.role : null,
      };
    });

    res.json(result);
  }
);

// Get messages for a course
app.get("/api/courses/:courseId/messages", authMiddleware, async (req, res) => {
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
});

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
          const meta = await uploadToCloudinary(
            file,
            "materials"
          );
          uploadedFiles.push(meta);
          course.materials.push(meta);
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

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
