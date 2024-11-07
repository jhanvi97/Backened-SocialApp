const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

const USERS_FILE = path.join(__dirname, "users.json");
const POSTS_FILE = path.join(__dirname, "posts.json");

const readJSONFile = (filePath) => {
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  }
  return [];
};

const writeJSONFile = (filePath, data) => {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
};

const authenticateJWT = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.sendStatus(403);
  jwt.verify(token, "your_jwt_secret", (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Middleware for role-based access control
const authorizeRole = (roles) => (req, res, next) => {
  const { role } = req.user;
  if (!roles.includes(role)) {
    return res.status(403).json({ message: "Access denied" });
  }
  next();
};

// User signup
app.post("/api/signup", (req, res) => {
  const { email, password, mobile, role = "user" } = req.body;
  const users = readJSONFile(USERS_FILE);

  if (users.some((user) => user.email === email || user.mobile === mobile)) {
    return res
      .status(400)
      .json({ message: "Email or mobile number already registered" });
  }

  const hashedPassword = bcrypt.hashSync(password, 8);
  const newUser = {
    email,
    password: hashedPassword,
    mobile,
    role,
    following: [],
    verified: true,
  };
  users.push(newUser);
  writeJSONFile(USERS_FILE, users);

  res.status(201).json({ message: "User registered successfully" });
});

// User login
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const users = readJSONFile(USERS_FILE);
  const user = users.find((u) => u.email === email);

  if (user && bcrypt.compareSync(password, user.password)) {
    const token = jwt.sign(
      { email: user.email, mobile: user.mobile, role: user.role },
      "your_jwt_secret",
      { expiresIn: "1h" }
    );
    return res.json({ token });
  }
  return res.status(401).json({ message: "Invalid email or password" });
});

// Create a new post
app.post("/api/posts", authenticateJWT, (req, res) => {
  const { title, description } = req.body;
  const posts = readJSONFile(POSTS_FILE);
  const newPost = {
    id: posts.length + 1,
    title,
    description,
    author: req.user.email,
    comments: [],
    likes: 0,
  };
  posts.push(newPost);
  writeJSONFile(POSTS_FILE, posts);
  res.status(201).json(newPost);
});

// Get all posts
app.get("/api/posts", (req, res) => {
  const posts = readJSONFile(POSTS_FILE);
  res.json(posts);
});

// Edit a post
app.put("/api/posts/:id", authenticateJWT, (req, res) => {
  const { id } = req.params;
  const { title, description } = req.body;
  const posts = readJSONFile(POSTS_FILE);
  const post = posts.find((p) => p.id == id);

  if (!post) return res.status(404).json({ message: "Post not found" });
  if (post.author !== req.user.email && req.user.role !== "admin") {
    return res
      .status(403)
      .json({ message: "You can only edit your own posts" });
  }

  post.title = title || post.title;
  post.description = description || post.description;
  writeJSONFile(POSTS_FILE, posts);
  res.json(post);
});

// Like or Unlike a post
app.post("/api/posts/:id/like", authenticateJWT, (req, res) => {
  const { id } = req.params;
  const userId = req.user.email; 
  const posts = readJSONFile(POSTS_FILE);
  const post = posts.find((p) => p.id == id);

  if (!post) return res.status(404).json({ message: "Post not found" });
  if (!Array.isArray(post.likedBy)) post.likedBy = [];

  const hasLiked = post.likedBy.includes(userId);

  if (hasLiked) {
    post.likedBy = post.likedBy.filter((email) => email !== userId); 
    post.likes = Math.max(post.likes - 1, 0); 
    message = "Post unliked successfully";
  } else {
    post.likedBy.push(userId); 
    post.likes += 1; 
    message = "Post liked successfully";
  }

  writeJSONFile(POSTS_FILE, posts);
  res.json({ message, likes: post.likes, likedBy: post.likedBy }); 
});


// Comment on a post
app.post("/api/posts/:id/comments", authenticateJWT, (req, res) => {
  const { id } = req.params;
  const { comment, parentCommentId = null } = req.body;
  const posts = readJSONFile(POSTS_FILE);
  const post = posts.find((p) => p.id == id);

  if (!post) return res.status(404).json({ message: "Post not found" });

  const newComment = {
    id: post.comments.length + 1,
    text: comment,
    author: req.user.email,
    replies: [],
  };

  if (parentCommentId) {
    const parentComment = post.comments.find((c) => c.id === parentCommentId);
    if (parentComment) {
      parentComment.replies.push(newComment);
    } else {
      return res.status(404).json({ message: "Parent comment not found" });
    }
  } else {
    post.comments.push(newComment);
  }

  writeJSONFile(POSTS_FILE, posts);
  res.status(201).json(post);
});

// Reply to a comment on a post
app.post("/api/posts/:id/comments/:commentId/reply", authenticateJWT, (req, res) => {
  const { id, commentId } = req.params;
  const { reply } = req.body; 
  const posts = readJSONFile(POSTS_FILE);
  const post = posts.find((p) => p.id == id); 

  if (!post) {
    return res.status(404).json({ message: "Post not found" });
  }

  const comment = post.comments.find((c) => c.id == commentId); 

  if (!comment) {
    return res.status(404).json({ message: "Comment not found" });
  }

  const newReply = {
    id: comment.replies.length + 1, 
    text: reply,
    author: req.user.email, 
  };

  comment.replies.push(newReply); 
  writeJSONFile(POSTS_FILE, posts); 

  res.status(201).json(comment); 
});


// Delete a comment
app.delete(
  "/api/posts/:postId/comments/:commentId",
  authenticateJWT,
  (req, res) => {
    const { postId, commentId } = req.params;
    const posts = readJSONFile(POSTS_FILE);
    const post = posts.find((p) => p.id == postId);

    if (!post) return res.status(404).json({ message: "Post not found" });

    const commentIndex = post.comments.findIndex((c) => c.id == commentId);
    if (commentIndex === -1)
      return res.status(404).json({ message: "Comment not found" });

    const comment = post.comments[commentIndex];
    if (
      comment.author !== req.user.email &&
      req.user.role !== "admin" &&
      post.author !== req.user.email
    ) {
      return res
        .status(403)
        .json({ message: "You can only delete your own comments" });
    }

    post.comments.splice(commentIndex, 1);
    writeJSONFile(POSTS_FILE, posts);
    res.status(204).send();
  }
);

// Admin functionality to delete posts
app.delete(
  "/api/posts/:id",
  authenticateJWT,
  authorizeRole(["admin"]),
  (req, res) => {
    const { id } = req.params;
    const posts = readJSONFile(POSTS_FILE);
    const postIndex = posts.findIndex((p) => p.id == id);

    if (postIndex === -1)
      return res.status(404).json({ message: "Post not found" });

    posts.splice(postIndex, 1);
    writeJSONFile(POSTS_FILE, posts);
    res.status(204).send();
  }
);

// Following functionality
app.post("/api/users/follow", authenticateJWT, (req, res) => {
  const { emailToFollow } = req.body;
  const users = readJSONFile(USERS_FILE);
  const currentUser = users.find((user) => user.email === req.user.email);
  const userToFollow = users.find((user) => user.email === emailToFollow);

  if (!userToFollow)
    return res.status(404).json({ message: "User to follow not found" });

  if (!currentUser.following.includes(emailToFollow)) {
    currentUser.following.push(emailToFollow);
    writeJSONFile(USERS_FILE, users);
  }

  res.json({ message: `You are now following ${emailToFollow}` });
});

// Unfollow functionality
app.post("/api/users/unfollow", authenticateJWT, (req, res) => {
  const { emailToUnfollow } = req.body;
  const users = readJSONFile(USERS_FILE);
  const currentUser = users.find((user) => user.email === req.user.email);
  const userToUnfollow = users.find((user) => user.email === emailToUnfollow);

  if (!userToUnfollow) {
    return res.status(404).json({ message: "User to unfollow not found" });
  }

  const index = currentUser.following.indexOf(emailToUnfollow);
  if (index > -1) {
    currentUser.following.splice(index, 1); 
    writeJSONFile(USERS_FILE, users);
    return res.json({ message: `You have unfollowed ${emailToUnfollow}` });
  } else {
    return res.status(400).json({ message: "You are not following this user" });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
