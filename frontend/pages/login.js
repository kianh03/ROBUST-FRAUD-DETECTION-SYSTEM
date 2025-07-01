import React, { useState } from 'react';
import { useAuth } from '../firebase/AuthContext';
import { useRouter } from 'next/router';
import Link from 'next/link';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const router = useRouter();

  async function handleSubmit(e) {
    e.preventDefault();

    try {
      setError('');
      setLoading(true);
      await login(email, password);
      router.push('/');
    } catch (err) {
      setError('Failed to log in: ' + err.message);
    }

    setLoading(false);
  }

  return (
    <div className="login-container">
      <h2>Login</h2>
      {error && <div className="alert alert-danger">{error}</div>}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button disabled={loading} type="submit" className="btn-login">
          Log In
        </button>
      </form>
      <div className="signup-link">
        Don't have an account? <Link href="/signup">Sign up</Link>
      </div>
      <div className="forgot-password">
        <Link href="/forgot-password">Forgot Password?</Link>
      </div>
    </div>
  );
} 