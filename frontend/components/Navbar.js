import React from 'react';
import Link from 'next/link';
import { useAuth } from '../firebase/AuthContext';
import { useRouter } from 'next/router';

export default function Navbar() {
  const { currentUser, logout } = useAuth();
  const router = useRouter();

  async function handleLogout() {
    try {
      await logout();
      router.push('/login');
    } catch (error) {
      console.error('Failed to log out', error);
    }
  }

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <Link href="/">Fraud Detection App</Link>
      </div>
      <div className="navbar-links">
        <Link href="/">Home</Link>
        {currentUser ? (
          <>
            <Link href="/dashboard">Dashboard</Link>
            <Link href="/profile">Profile</Link>
            <span className="user-email">{currentUser.email}</span>
            <button onClick={handleLogout} className="btn-logout">
              Log Out
            </button>
          </>
        ) : (
          <>
            <Link href="/login">Login</Link>
            <Link href="/signup">Sign Up</Link>
          </>
        )}
      </div>
    </nav>
  );
} 