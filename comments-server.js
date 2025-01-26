import cors from "cors"
import debug from "debug"
import createDOMPurify from "dompurify"
import express from "express"
import rateLimit from "express-rate-limit"
import { JSDOM } from "jsdom"
import { marked } from "marked"
import { MongoClient } from "mongodb"

const info = debug("server | info |")
const warn = debug("server | WARN |")
debug.enable("server *")

const config = {
    mongoUri: process.env.MONGODB_URI,
    proxyIP: process.env.PROXY_IP,

    port: parseInt(process.env.PORT, 10) || 3000,
    dbName: process.env.MONGODB_DB || "one137-web",
    collectionName: process.env.MONGODB_COLLECTION || "comments",
    allowedOriginRE: process.env.ALLOWED_ORIGIN_RE || "^https://one137\.dev$",

    // Read/write limits:
    rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 5 * 60 * 1000,
    writeRateLimit: parseInt(process.env.WRITE_RATE_LIMIT, 10) || 5,
    readRateLimit: parseInt(process.env.READ_RATE_LIMIT, 10) || 60,
    maxComments: parseInt(process.env.MAX_COMMENTS, 10) || 100,

    // Reject comments written in less than 3sec (most likely bots):
    minSubmitTime: parseInt(process.env.MIN_SUBMIT_TIME_MS, 10) || 3000,

    // These values should match the corresponding HTML maxlength on the frontend:
    maxAuthorLength: parseInt(process.env.MAX_AUTHOR_LENGTH, 10) || 50,
    maxMessageLength: parseInt(process.env.MAX_MESSAGE_LENGTH, 10) || 5000,
}

const app = express()

// Middleware setup
app.set("trust proxy", process.env.PROXY_IP)
app.use(express.json({ limit: "1kb" }))
app.use(cors({ origin: new RegExp(config.allowedOriginRE) }))

// MongoDB setup

const client = new MongoClient(config.mongoUri)
let isConnected = false

async function connect() {
    try {
        await client.connect()
        await client.db("admin").command({ ping: 1 })
        isConnected = true
        info("Connected to MongoDB")
    } catch (error) {
        warn("Could not connect to MongoDB:", error)
        process.exit(1)
    }
}

// Input parsing, cleanup and validation

// Configure marked (parse markdown to html)
marked.setOptions({
    headerIds: false,
    mangle: false,
    breaks: true,
    gfm: true,
    silent: true
})

// Initialize DOMPurify (limit allowed html tags)
const { window } = new JSDOM("")
const DOMPurify = createDOMPurify(window)

// Input validation helpers
const isValidInput = (input, maxLength) => {
    return input &&
           typeof input === "string" &&
           input.trim().length > 0 &&
           input.trim().length <= maxLength
}
const isValidSubmissionTime = (timestamp) => {
    const submissionTime = Date.now() - parseInt(timestamp)
    return !isNaN(submissionTime) && submissionTime >= config.minSubmitTime
}

// Route handlers

const getClientIp = (req) => req.headers['cf-connecting-ip'] ?? req.ip

const healthCheckHandler = (req, res) => {
    info(`GET /health from ${getClientIp(req)}`)
    res.status(isConnected ? 200 : 500).json({ status: isConnected ? "ok" : "error" })
}

const getCommentsHandler = async (req, res) => {
    const pageName = req.query.pageName
    info(`GET /comments for ${pageName} from ${getClientIp(req)}`)

    if (!isConnected) {
        warn('GET /comments failed: MongoDB not connected')
        return res.status(503).json({ error: "Service unavailable" })
    }

    try {
        const comments = await client
            .db(config.dbName)
            .collection(config.collectionName)
            .find({ pageName })
            .project({ author: 1, message: 1, timestamp: 1 })
            .sort({ timestamp: -1 })
            .limit(config.maxComments)
            .toArray()

        res.json(comments)
    } catch (error) {
        warn("GET /comments error:", error)
        res.status(500).json({ error: "Failed to fetch comments" })
    }
}

const addEntryHandler = async (req, res) => {
    const pageName = req.query.pageName
    info(`POST /comments for ${pageName} from ${getClientIp(req)}`)
    if (!isConnected) {
        warn('POST /comments failed: MongoDB not connected')
        return res.status(503).json({ error: "Service unavailable" })
    }

    const { author, message, contact, timestamp } = req.body

    // Spam checks
    if (contact || !isValidSubmissionTime(timestamp)) {
        warn('POST /comments rejected: spam check failed')
        return res.status(400).json({ error: "Invalid submission" })
    }

    // Input validation
    if (!pageName) {
        warn("POST /comments rejected: missing pageName parameter")
        return res.status(400).json({ error: "pageName is required" })
    }
    if (!isValidInput(author, config.maxAuthorLength) || !isValidInput(message, config.maxMessageLength)) {
        warn('POST /comments rejected: invalid input length')
        return res.status(400).json({ error: "Invalid input" })
    }

    const sanitizedAuthor = author.trim()
    const sanitizedMessage = message.trim()

    // Convert markdown to HTML and sanitize
    const renderedMarkdown = marked.parse(sanitizedMessage)
    const cleanHtml = DOMPurify.sanitize(renderedMarkdown, {
        ALLOWED_TAGS: ["p", "br", "strong", "em", "code", "pre", "ul", "ol", "li", "blockquote"],
        ALLOWED_ATTR: []
    })

    try {
        const result = await client
            .db(config.dbName)
            .collection(config.collectionName)
            .insertOne({
                pageName,
                author: sanitizedAuthor,
                message: cleanHtml,
                timestamp: new Date(),
                clientIp: getClientIp(req),
                clientUserAgent: req.headers['user-agent'],
            })
        res.sendStatus(201)
    } catch (error) {
        warn('POST /comments error:', error)
        res.status(500).json({ error: "Failed to add entry" })
    }
}

// Rate limiting setup

const createLimiter = (max) => rateLimit({
    windowMs: config.rateLimitWindow,
    max,
    skipFailedRequests: true,
    keyGenerator: getClientIp,
    message: { error: "Too many requests, please try again later" }
})

const writeLimiter = createLimiter(config.writeRateLimit)
const readLimiter = createLimiter(config.readRateLimit)

// Routes creation
app.get("/comments-api/health", readLimiter, healthCheckHandler)
app.get("/comments-api/comments", readLimiter, getCommentsHandler)
app.post("/comments-api/comments", writeLimiter, addEntryHandler)

// Graceful shutdown
async function shutdown() {
    info("Shutting down gracefully...")
    if (client) {
        await client.close()
    }
    process.exit(0)
}

process.on("SIGTERM", shutdown)
process.on("SIGINT", shutdown)

// Start server
connect().then(() => {
    app.listen(config.port, () => {
        info(`Comments API listening on port ${config.port}`)
    })
})
