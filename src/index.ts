import { Hono } from "hono";
import { cors } from "hono/cors";
import { PrismaClient, Prisma } from "@prisma/client";
import { HTTPException } from "hono/http-exception";
import { decode, sign, verify } from "hono/jwt";
import { jwt } from 'hono/jwt'
import type { JwtVariables } from 'hono/jwt'
import axios from 'axios';

type Variables = JwtVariables

const app = new Hono<{ Variables: Variables }>()

const prisma = new PrismaClient();

app.use("/*", cors());

app.use(
  "/protected/*",
  jwt({
    secret: 'mySecretKey',
  })
);

// Register user
app.post("/register", async (c) => {
  try {
    const body = await c.req.json();

    const bcryptHash = await Bun.password.hash(body.password, {
      algorithm: "bcrypt",
      cost: 4, // number between 4-31
    });

    const user = await prisma.user.create({
      data: {
        email: body.email,
        username: body.username,
        hashedPassword: bcryptHash,
      },
    });

    return c.json({ message: `${user.email} created successfully}` });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError) {
      if (e.code === "P2002") {
        console.log("There is a unique constraint violation, a new user cannot be created with this email");
        return c.json({ message: "Email already exists" });
      }
    }
  }
});

// Login user
app.post("/login", async (c) => {
  try {
    const body = await c.req.json();
    const user = await prisma.user.findUnique({
      where: { email: body.email },
      select: { id: true, hashedPassword: true },
    });

    if (!user) {
      return c.json({ message: "User not found" });
    }

    const match = await Bun.password.verify(
      body.password,
      user.hashedPassword,
      "bcrypt"
    );
    if (match) {
      const payload = {
        sub: user.id,
        exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expires in 60 minutes
      };
      const secret = "mySecretKey";
      const token = await sign(payload, secret);
      return c.json({ message: "Login successful", token: token });
    } else {
      throw new HTTPException(401, { message: "Invalid credentials" });
    }
  } catch (error) {
    throw new HTTPException(401, { message: "Invalid credentials" });
  }
});

// Read user profile
app.get("/protected/profile", async (c) => {
  const userId = c.req.headers.get("sub");

  try {
    const user = await prisma.user.findUnique({
      where: { id: parseInt(userId) },
      select: { id: true, email: true, username: true },
    });

    if (!user) {
      return c.json({ message: "User not found" }, 404);
    }

    return c.json(user);
  } catch (error) {
    throw new HTTPException(500, { message: "Internal server error" });
  }
});

// Update user profile
app.put("/protected/profile", async (c) => {
  const userId = c.req.headers.get("sub");
  const body = await c.req.json();

  try {
    const user = await prisma.user.update({
      where: { id: parseInt(userId) },
      data: {
        email: body.email,
        username: body.username,
      },
      select: { id: true, email: true, username: true },
    });

    return c.json({ message: "Profile updated successfully", user });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      return c.json({ message: "Email already exists" });
    }
    throw new HTTPException(500, { message: "Internal server error" });
  }
});

// Delete user profile
app.delete("/protected/profile", async (c) => {
  const userId = c.req.headers.get("sub");

  try {
    await prisma.user.delete({
      where: { id: parseInt(userId) },
    });

    return c.json({ message: "Profile deleted successfully" });
  } catch (error) {
    throw new HTTPException(500, { message: "Internal server error" });
  }
});

export default app;
