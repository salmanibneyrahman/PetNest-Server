const dns = require("node:dns").promises;
dns.setServers(["1.1.1.1", "8.8.8.8"]);

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;

app.use(
    cors({
        origin: [
            "http://localhost:3000",
            process.env.FRONTEND_URL || "http://localhost:3000",
        ],
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);

app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

let petsCollection;
let requestsCollection;
let usersCollection;

async function connectDB() {
    try {
        await client.connect();
        const db = client.db(process.env.DB_NAME || "petnest");
        petsCollection = db.collection("pets");
        requestsCollection = db.collection("requests");
        usersCollection = db.collection("users");
        console.log("Connected to MongoDB successfully");
    } catch (error) {
        console.error("MongoDB connection error:", error);
        process.exit(1);
    }
}

connectDB();

// ─── JWKS-BASED JWT VERIFICATION ─────────────────────────────────────────────

const { createRemoteJWKSet, jwtVerify } = require("jose-cjs");

const JWKS_URL = process.env.FRONTEND_URL
    ? `${process.env.FRONTEND_URL}/api/auth/jwks`
    : "http://localhost:3000/api/auth/jwks";

let remoteJWKS = null;

function getRemoteJWKS() {
    if (!remoteJWKS) {
        remoteJWKS = createRemoteJWKSet(new URL(JWKS_URL), {
            cacheMaxAge: 10 * 60 * 1000,
        });
    }
    return remoteJWKS;
}

async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res
            .status(401)
            .json({ error: "Unauthorized: No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const JWKS = getRemoteJWKS();
        const { payload } = await jwtVerify(token, JWKS, {
            issuer: process.env.FRONTEND_URL || "http://localhost:3000",
        });
        req.user = payload;
        next();
    } catch (err) {
        console.error("Token verification error:", err.message);
        return res
            .status(403)
            .json({ error: "Forbidden: Invalid or expired token" });
    }
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

app.post("/api/auth/register", async (req, res) => {
    try {
        const { name, email, photoURL } = req.body;

        if (!name || !email) {
            return res
                .status(400)
                .json({ error: "Name and email are required" });
        }

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.status(200).json({ message: "User already exists", existing: true });
        }

        const newUser = {
            name,
            email,
            photoURL: photoURL || "",
            createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);
        res.status(201).json({
            message: "User registered successfully",
            userId: result.insertedId,
        });
    } catch (error) {
        console.error("Register error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/api/auth/user/:email", verifyToken, async (req, res) => {
    try {
        const { email } = req.params;

        const tokenEmail =
            req.user.email || req.user.sub || req.user["user.email"];

        if (tokenEmail !== email) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.status(200).json(user);
    } catch (error) {
        console.error("Get user error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// ─── PETS ROUTES ─────────────────────────────────────────────────────────────

app.get("/api/pets", async (req, res) => {
    try {
        const { search, species, sort } = req.query;
        const query = {};

        if (search) {
            query.name = { $regex: search, $options: "i" };
        }

        if (species && species !== "all") {
            const speciesArray = species.split(",").map((s) => s.trim());
            query.species = { $in: speciesArray };
        }

        let sortOption = { createdAt: -1 };
        if (sort === "oldest") {
            sortOption = { createdAt: 1 };
        } else if (sort === "price_asc") {
            sortOption = { adoptionFee: 1 };
        } else if (sort === "price_desc") {
            sortOption = { adoptionFee: -1 };
        }

        const pets = await petsCollection.find(query).sort(sortOption).toArray();
        res.status(200).json(pets);
    } catch (error) {
        console.error("Get pets error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/api/pets/featured", async (req, res) => {
    try {
        const pets = await petsCollection
            .find({ status: { $ne: "adopted" } })
            .sort({ createdAt: -1 })
            .limit(6)
            .toArray();
        res.status(200).json(pets);
    } catch (error) {
        console.error("Get featured pets error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/api/pets/owner/:email", verifyToken, async (req, res) => {
    try {
        const { email } = req.params;

        const tokenEmail =
            req.user.email || req.user.sub || req.user["user.email"];

        if (tokenEmail !== email) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const pets = await petsCollection
            .find({ ownerEmail: email })
            .sort({ createdAt: -1 })
            .toArray();

        res.status(200).json(pets);
    } catch (error) {
        console.error("Get owner pets error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/api/pets/:id", async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid pet ID" });
        }

        const pet = await petsCollection.findOne({ _id: new ObjectId(id) });
        if (!pet) {
            return res.status(404).json({ error: "Pet not found" });
        }

        res.status(200).json(pet);
    } catch (error) {
        console.error("Get pet error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/api/pets", verifyToken, async (req, res) => {
    try {
        const {
            name,
            species,
            breed,
            age,
            gender,
            imageURL,
            healthStatus,
            vaccinationStatus,
            location,
            adoptionFee,
            description,
            ownerEmail,
        } = req.body;

        const tokenEmail =
            req.user.email || req.user.sub || req.user["user.email"];

        if (tokenEmail !== ownerEmail) {
            return res.status(403).json({ error: "Forbidden" });
        }

        if (!name || !species || !ownerEmail) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const newPet = {
            name,
            species,
            breed: breed || "",
            age: age || "",
            gender: gender || "",
            imageURL: imageURL || "",
            healthStatus: healthStatus || "",
            vaccinationStatus: vaccinationStatus || false,
            location: location || "",
            adoptionFee: parseFloat(adoptionFee) || 0,
            description: description || "",
            ownerEmail,
            status: "available",
            views: 0,
            saves: 0,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        const result = await petsCollection.insertOne(newPet);
        res.status(201).json({
            message: "Pet added successfully",
            petId: result.insertedId,
        });
    } catch (error) {
        console.error("Add pet error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.put("/api/pets/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid pet ID" });
        }

        const pet = await petsCollection.findOne({ _id: new ObjectId(id) });
        if (!pet) {
            return res.status(404).json({ error: "Pet not found" });
        }

        const tokenEmail =
            req.user.email || req.user.sub || req.user["user.email"];

        if (pet.ownerEmail !== tokenEmail) {
            return res.status(403).json({ error: "Forbidden: Not the owner" });
        }

        const {
            name,
            species,
            breed,
            age,
            gender,
            imageURL,
            healthStatus,
            vaccinationStatus,
            location,
            adoptionFee,
            description,
        } = req.body;

        const updatedPet = {
            name,
            species,
            breed,
            age,
            gender,
            imageURL,
            healthStatus,
            vaccinationStatus,
            location,
            adoptionFee: parseFloat(adoptionFee) || 0,
            description,
            updatedAt: new Date(),
        };

        await petsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updatedPet }
        );

        res.status(200).json({ message: "Pet updated successfully" });
    } catch (error) {
        console.error("Update pet error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.delete("/api/pets/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid pet ID" });
        }

        const pet = await petsCollection.findOne({ _id: new ObjectId(id) });
        if (!pet) {
            return res.status(404).json({ error: "Pet not found" });
        }

        const tokenEmail =
            req.user.email || req.user.sub || req.user["user.email"];

        if (pet.ownerEmail !== tokenEmail) {
            return res.status(403).json({ error: "Forbidden: Not the owner" });
        }

        await petsCollection.deleteOne({ _id: new ObjectId(id) });
        await requestsCollection.deleteMany({ petId: id });

        res.status(200).json({ message: "Pet deleted successfully" });
    } catch (error) {
        console.error("Delete pet error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.patch("/api/pets/:id/increment-view", async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid pet ID" });
        }

        await petsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $inc: { views: 1 } }
        );

        res.status(200).json({ message: "View count incremented" });
    } catch (error) {
        console.error("Increment view error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// ─── REQUESTS ROUTES ─────────────────────────────────────────────────────────

app.post("/api/requests", verifyToken, async (req, res) => {
    try {
        const {
            petId,
            petName,
            ownerEmail,
            userName,
            userEmail,
            pickupDate,
            message,
        } = req.body;

        const tokenEmail =
            req.user.email || req.user.sub || req.user["user.email"];

        if (tokenEmail !== userEmail) {
            return res.status(403).json({ error: "Forbidden" });
        }

        if (ownerEmail === userEmail) {
            return res.status(400).json({
                error: "Pet owners cannot submit adoption requests for their own pets",
            });
        }

        if (!ObjectId.isValid(petId)) {
            return res.status(400).json({ error: "Invalid pet ID" });
        }

        const pet = await petsCollection.findOne({ _id: new ObjectId(petId) });
        if (!pet) {
            return res.status(404).json({ error: "Pet not found" });
        }

        if (pet.status === "adopted") {
            return res
                .status(400)
                .json({ error: "This pet has already been adopted" });
        }

        const existingRequest = await requestsCollection.findOne({
            petId,
            userEmail,
        });

        if (existingRequest) {
            return res.status(409).json({
                error: "You have already submitted a request for this pet",
            });
        }

        const newRequest = {
            petId,
            petName,
            ownerEmail,
            userName,
            userEmail,
            pickupDate,
            message: message || "",
            status: "pending",
            requestDate: new Date(),
        };

        const result = await requestsCollection.insertOne(newRequest);
        res.status(201).json({
            message: "Adoption request submitted successfully",
            requestId: result.insertedId,
        });
    } catch (error) {
        console.error("Submit request error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/api/requests/user/:email", verifyToken, async (req, res) => {
    try {
        const { email } = req.params;

        const tokenEmail =
            req.user.email || req.user.sub || req.user["user.email"];

        if (tokenEmail !== email) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const requests = await requestsCollection
            .find({ userEmail: email })
            .sort({ requestDate: -1 })
            .toArray();

        res.status(200).json(requests);
    } catch (error) {
        console.error("Get user requests error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/api/requests/pet/:petId", verifyToken, async (req, res) => {
    try {
        const { petId } = req.params;

        if (!ObjectId.isValid(petId)) {
            return res.status(400).json({ error: "Invalid pet ID" });
        }

        const pet = await petsCollection.findOne({ _id: new ObjectId(petId) });
        if (!pet) {
            return res.status(404).json({ error: "Pet not found" });
        }

        const tokenEmail =
            req.user.email || req.user.sub || req.user["user.email"];

        if (pet.ownerEmail !== tokenEmail) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const requests = await requestsCollection
            .find({ petId })
            .sort({ requestDate: -1 })
            .toArray();

        res.status(200).json(requests);
    } catch (error) {
        console.error("Get pet requests error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.patch("/api/requests/:id/status", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid request ID" });
        }

        if (!["approved", "rejected"].includes(status)) {
            return res.status(400).json({ error: "Invalid status value" });
        }

        const request = await requestsCollection.findOne({
            _id: new ObjectId(id),
        });

        if (!request) {
            return res.status(404).json({ error: "Request not found" });
        }

        if (!ObjectId.isValid(request.petId)) {
            return res.status(400).json({ error: "Invalid pet ID in request" });
        }

        const pet = await petsCollection.findOne({
            _id: new ObjectId(request.petId),
        });

        if (!pet) {
            return res.status(404).json({ error: "Pet not found" });
        }

        const tokenEmail =
            req.user.email || req.user.sub || req.user["user.email"];

        if (pet.ownerEmail !== tokenEmail) {
            return res.status(403).json({ error: "Forbidden" });
        }

        if (status === "approved") {
            const existingApproved = await requestsCollection.findOne({
                petId: request.petId,
                status: "approved",
            });

            if (existingApproved) {
                return res.status(400).json({
                    error: "Another request has already been approved for this pet",
                });
            }

            await requestsCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { status: "approved" } }
            );

            await petsCollection.updateOne(
                { _id: new ObjectId(request.petId) },
                { $set: { status: "adopted" } }
            );

            await requestsCollection.updateMany(
                {
                    petId: request.petId,
                    _id: { $ne: new ObjectId(id) },
                    status: "pending",
                },
                { $set: { status: "rejected" } }
            );
        } else {
            await requestsCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { status: "rejected" } }
            );
        }

        res.status(200).json({ message: `Request ${status} successfully` });
    } catch (error) {
        console.error("Update request status error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.delete("/api/requests/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid request ID" });
        }

        const request = await requestsCollection.findOne({
            _id: new ObjectId(id),
        });

        if (!request) {
            return res.status(404).json({ error: "Request not found" });
        }

        const tokenEmail =
            req.user.email || req.user.sub || req.user["user.email"];

        if (request.userEmail !== tokenEmail) {
            return res.status(403).json({ error: "Forbidden" });
        }

        await requestsCollection.deleteOne({ _id: new ObjectId(id) });
        res.status(200).json({ message: "Request cancelled successfully" });
    } catch (error) {
        console.error("Delete request error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────

app.get("/", (req, res) => {
    res.status(200).json({ message: "PetNest API is running" });
});

app.use((req, res) => {
    res.status(404).json({ error: "Route not found" });
});

app.listen(port, () => {
    console.log(`PetNest server running on port ${port}`);
    console.log(`JWKS endpoint: ${JWKS_URL}`);
});