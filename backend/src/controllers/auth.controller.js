import cloudinary from "../lib/cloudinary.js";
import { generateToken } from "../lib/utils.js";
import { User } from "../models/user.model.js";
import bcryptjs from "bcryptjs";

export async function signup(req, res) {
  const { fullName, email, password } = req.body;
  try {
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    const user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "Email already exists" });

    const salt = await bcryptjs.genSalt(10);
    const hashedPassword = await bcryptjs.hash(password, salt);

    const newUser = new User({ email, fullName, password: hashedPassword });

    if (newUser) {
      generateToken(newUser._id, res);
      await newUser.save();
      return res.status(201).json({
        _id: newUser._id,
        email,
        fullName,
        message: "User created",
      });
    } else {
      return res.status(400).json({ message: "Invalid User Data" });
    }
  } catch (error) {
    console.log("Error occurred in ", error);
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function login(req, res) {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const isPasswordCorrect = await bcryptjs.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    generateToken(user._id, res);
    return res.status(200).json({
      _id: user._id,
      email: user.email,
      fullName: user.fullName,
      message: "User loggedIn",
    });
  } catch (error) {
    console.log("Error in login() ", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function logout(req, res) {
  try {
    res.cookie("jwt", "", { maxAge: 0 });
    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.log("Error in logout() ", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function updateProfile(req, res) {
  try {
    const { profilePic } = req.body;
    const userId = req.user._id;

    if (!profilePic) {
      return res.status(400).json({ message: "Profile pic is required" });
    }

    const uploadResponse = await cloudinary.uploader.upload(profilePic);
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        profilePic: uploadResponse.secure_url,
      },
      { new: true }
    );

    res.status(200).json(updatedUser);
  } catch (error) {
    console.log("Error in updateProfile() ", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function checkAuth(req, res) {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    console.log("Error in checkAuth() ", error);
    res.status(500).json({ message: "Internal server error" });
  }
}
