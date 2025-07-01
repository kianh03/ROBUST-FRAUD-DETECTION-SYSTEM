import React, { useState } from 'react';
import { useAuth } from '../firebase/AuthContext';
import { useRouter } from 'next/router';
import Navbar from '../components/Navbar';
import ProtectedRoute from '../components/ProtectedRoute';

function Profile() {
  const { currentUser, updateUserProfile } = useAuth();
  const [name, setName] = useState(currentUser?.displayName || '');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const router = useRouter();

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      setError('');
      setMessage('');
      setLoading(true);
      
      await updateUserProfile(currentUser, {
        displayName: name
      });
      
      setMessage('Profile updated successfully!');
    } catch (err) {
      setError('Failed to update profile: ' + err.message);
    }
    
    setLoading(false);
  };

  return (
    <div>
      <Navbar />
      <div className="profile-container">
        <h1>Profile</h1>
        <div className="profile-info">
          <p><strong>Email:</strong> {currentUser.email}</p>
        </div>
        
        {error && <div className="alert alert-danger">{error}</div>}
        {message && <div className="alert alert-success">{message}</div>}
        
        <form onSubmit={handleSubmit} className="profile-form">
          <div className="form-group">
            <label htmlFor="name">Display Name</label>
            <input 
              type="text" 
              id="name" 
              value={name} 
              onChange={(e) => setName(e.target.value)} 
            />
          </div>
          
          <button type="submit" className="btn-update" disabled={loading}>
            {loading ? 'Updating...' : 'Update Profile'}
          </button>
        </form>
      </div>
    </div>
  );
}

export default function ProtectedProfile() {
  return (
    <ProtectedRoute>
      <Profile />
    </ProtectedRoute>
  );
} 