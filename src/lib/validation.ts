import { z } from 'zod';

const email = z
  .string()
  .trim()
  .toLowerCase()
  .max(254, 'Email too long')
  .pipe(z.email('Enter a valid email'));

// NIST 800-63B style: length over composition rules. Upper bound stops hash-DoS.
const newPassword = z
  .string()
  .min(12, 'Password must be at least 12 characters')
  .max(128, 'Password must be at most 128 characters')
  .refine((p) => /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p), 'Use upper-case, lower-case and a digit')
  .refine((p) => new Set(p).size >= 6, 'Password is too repetitive');

export const registerSchema = z.object({ email, password: newPassword }).strict();
export const loginSchema = z.object({ email, password: z.string().min(1).max(128) }).strict();
export const mfaSchema = z.object({ code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code') }).strict();
