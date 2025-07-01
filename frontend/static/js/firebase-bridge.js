// This file serves as a bridge between the HTML templates and React components
// It exposes Firebase authentication methods to the global window object

document.addEventListener('DOMContentLoaded', function() {
  // Check if we're in a Next.js environment (ReactJS)
  const isReactEnvironment = typeof window !== 'undefined' && window.__NEXT_DATA__;
  
  // If we're not in a React environment, we need to manually
  // handle routing and auth state changes
  if (!isReactEnvironment) {
    // Check if the user is authenticated on page load
    firebase.auth().onAuthStateChanged(function(user) {
      // Store user info in sessionStorage for access across pages
      if (user) {
        sessionStorage.setItem('user', JSON.stringify({
          uid: user.uid,
          email: user.email,
          displayName: user.displayName,
          emailVerified: user.emailVerified
        }));
      } else {
        sessionStorage.removeItem('user');
      }
      
      // Protected pages logic - redirect if not authenticated
      const protectedPaths = ['/dashboard', '/profile', '/settings'];
      const currentPath = window.location.pathname;
      
      // If on a protected path and not logged in, redirect to login
      if (protectedPaths.includes(currentPath) && !user) {
        window.location.href = '/login';
      }
      
      // If on login or register and already logged in, redirect to dashboard
      if ((currentPath === '/login' || currentPath === '/register' || currentPath === '/signup') && user) {
        window.location.href = '/dashboard';
      }
    });
  }
  
  // Expose a global method to get the current auth status
  window.getAuthStatus = function() {
    return new Promise((resolve) => {
      firebase.auth().onAuthStateChanged(function(user) {
        resolve(user);
      });
    });
  };
  
  // Add logout functionality to any logout buttons outside React
  const logoutButtons = document.querySelectorAll('.logout-button');
  if (logoutButtons.length > 0) {
    logoutButtons.forEach(button => {
      button.addEventListener('click', function(e) {
        e.preventDefault();
        firebase.auth().signOut().then(() => {
          window.location.href = '/login';
        });
      });
    });
  }
}); 