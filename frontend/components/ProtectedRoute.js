import React, { useEffect } from 'react';
import { useRouter } from 'next/router';
import { useAuth } from '../firebase/AuthContext';

export default function ProtectedRoute({ children }) {
  const { currentUser } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!currentUser) {
      router.push('/login');
    }
  }, [currentUser, router]);

  return currentUser ? children : null;
} 