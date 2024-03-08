import express from 'express';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import { prisma } from '../../prisma';
import bcrypt from 'bcrypt';

const router = express.Router();

router.post('/password-reset-link', async (req, res) => {
  const { email } = req.body;

  try {
    // 1. Verify if email is in database
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(404).send({ error: "Email not found." });
    }

    // 2. Generate a reset token and expiry date for the user
    const token = crypto.randomBytes(20).toString('hex');
    const resetLink = `${process.env.FRONTEND_URL}/password-reset/${token}`;

    await prisma.user.update({
      where: { email: user.email },
      data: {
        resetToken: token,
        resetTokenExpiry: Date.now() + 3600000, // 1 hour from now
      },
    });

    // 3. Create a transporter object using the default SMTP transport
    const transporter = nodemailer.createTransport({
      service: 'gmail', // Use your preferred email service
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // 4. Set email content
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset',
      text: `Click the link below to reset your password:\n\n${resetLink}\n\nIf you did not request a password reset, please ignore this email.`
    };

    // 5. Send the email
    await transporter.sendMail(mailOptions);
    res.status(200).send({ message: 'Reset email sent successfully.' });
  } catch (error) {
    console.error("An error occurred:", error);
    return res.status(500).send({ error: "An unexpected error occurred." });
  }
});

router.post('/password-reset/confirm', async (req, res) => {
  const { token, password } = req.body;

  try {
    // 1. Find the user by the token and ensure the token hasn't expired
    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpiry: {
          gte: Date.now(),
        },
      },
    });

    if (!user) {
      return res.status(400).send({ error: "Token is invalid or has expired." });
    }

    // 2. Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Update the user's password and clear the reset token
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiry: null,
      },
    });

    // 4. Send a success response
    res.status(200).send({ message: "Password has been reset successfully." });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).send({ error: 'Internal server error.' });
  }
});

export default router;
