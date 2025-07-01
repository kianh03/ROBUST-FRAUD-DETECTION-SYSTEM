import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import { useAuth } from '../firebase/AuthContext';
import ProtectedRoute from '../components/ProtectedRoute';
import Navbar from '../components/Navbar';

function Dashboard() {
  const { currentUser } = useAuth();
  const [userActivity, setUserActivity] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // In a real implementation, you would fetch the user's activity from your backend
    // This is just a placeholder
    const fetchUserActivity = async () => {
      try {
        setLoading(true);
        // Mock data for demonstration
        setTimeout(() => {
          setUserActivity([
            { id: 1, url: 'https://example.com', riskScore: 25, date: new Date().toISOString() },
            { id: 2, url: 'https://suspicious-site.com', riskScore: 85, date: new Date(Date.now() - 86400000).toISOString() },
            // Add more mock data as needed
          ]);
          setLoading(false);
        }, 1000);
      } catch (error) {
        console.error('Error fetching user activity:', error);
        setLoading(false);
      }
    };

    fetchUserActivity();
  }, []);

  const getRiskLabel = (score) => {
    if (score < 30) return 'Low Risk';
    if (score < 70) return 'Medium Risk';
    return 'High Risk';
  };

  const getRiskColor = (score) => {
    if (score < 30) return 'green';
    if (score < 70) return 'orange';
    return 'red';
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  };

  return (
    <div className="dashboard-container">
      <Navbar />
      <div className="dashboard-content">
        <h1>Dashboard</h1>
        <div className="user-info">
          <h2>Welcome, {currentUser?.displayName || currentUser?.email}</h2>
          <p>Email: {currentUser?.email}</p>
        </div>

        <div className="activity-section">
          <h3>Recent Activity</h3>
          {loading ? (
            <p>Loading your activity...</p>
          ) : userActivity.length > 0 ? (
            <table className="activity-table">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Risk Score</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {userActivity.map((activity) => (
                  <tr key={activity.id}>
                    <td>{activity.url}</td>
                    <td style={{ color: getRiskColor(activity.riskScore) }}>
                      {activity.riskScore}% - {getRiskLabel(activity.riskScore)}
                    </td>
                    <td>{formatDate(activity.date)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p>No activity found. Start analyzing URLs to see your history.</p>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ProtectedDashboard() {
  return (
    <ProtectedRoute>
      <Dashboard />
    </ProtectedRoute>
  );
} 