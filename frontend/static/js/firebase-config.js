// Firebase Configuration
const firebaseConfig = {
  apiKey: "AIzaSyD4iOeFtD-hETA5-8qWh9wRk-PNdhVKj-E",
  authDomain: "fraudtest-23c54.firebaseapp.com",
  projectId: "fraudtest-23c54",
  storageBucket: "fraudtest-23c54.appspot.com",
  messagingSenderId: "265409594914",
  appId: "1:265409594914:web:e199246e50428971c32c7b"
};

// Initialize Firebase
try {
  firebase.initializeApp(firebaseConfig);
  console.log("Firebase initialized successfully");
} catch (error) {
  console.error("Error initializing Firebase:", error);
}

// Initialize Firestore when the script loads
document.addEventListener('DOMContentLoaded', function() {
  console.log("DOM content loaded, initializing Firestore");
  setTimeout(() => {
    // Properly wait for Firebase Firestore to be available
    if (typeof firebase !== 'undefined' && typeof firebase.firestore === 'function') {
      console.log("Firestore is available, initializing");
      const initialized = firestoreDb.init();
      console.log("Firestore initialization result:", initialized);
      
      if (initialized) {
        // Initialize user data when a user logs in
        firebase.auth().onAuthStateChanged((user) => {
          console.log("Auth state changed, user:", user ? user.uid : "no user");
          
          if (user) {
            // Initialize user data in Firestore if it doesn't exist
            firestoreDb.initializeUserData(user.uid);
          }
        });
      }
    } else {
      console.error("Firestore is not available after timeout");
    }
  }, 1000); // Give Firebase some time to fully load
});

// Firebase Auth helper object
const firebaseAuth = {
  // Check the current auth state
  checkAuthState: function(callback) {
    firebase.auth().onAuthStateChanged(callback);
  },
  
  // Sign up with email/password
  signUp: function(email, password) {
    return firebase.auth().createUserWithEmailAndPassword(email, password);
  },
  
  // Sign in with email/password
  signIn: function(email, password) {
    return firebase.auth().signInWithEmailAndPassword(email, password);
  },
  
  // Sign in with Google
  signInWithGoogle: function() {
    const provider = new firebase.auth.GoogleAuthProvider();
    return firebase.auth().signInWithPopup(provider);
  },
  
  // Sign out
  signOut: function() {
    return firebase.auth().signOut();
  },
  
  // Reset password
  resetPassword: function(email) {
    return firebase.auth().sendPasswordResetEmail(email);
  },
  
  // Update profile
  updateProfile: function(displayName) {
    const user = firebase.auth().currentUser;
    if (user) {
        return user.updateProfile({
        displayName: displayName
        });
    } else {
      return Promise.reject(new Error("No user is signed in"));
    }
  },
  
  // Send email verification
  sendEmailVerification: function() {
    const user = firebase.auth().currentUser;
    if (user) {
      return user.sendEmailVerification();
    } else {
      return Promise.reject(new Error("No user is signed in"));
    }
  },
  
  // Get current user
  getCurrentUser: function() {
    return firebase.auth().currentUser;
  }
};

// Firestore helpers
const firestoreDb = {
  // Initialize Firestore
  db: null,
  
  // Initialize Firestore when it's loaded
  init: function() {
    try {
      if (typeof firebase !== 'undefined' && typeof firebase.firestore === 'function') {
        this.db = firebase.firestore();
        console.log("Firestore initialized successfully");
        return true;
      } else {
        console.warn("Firestore not available yet, firebase.firestore is:", typeof firebase.firestore);
        return false;
      }
    } catch (error) {
      console.error("Error initializing Firestore:", error);
      return false;
    }
  },
  
  // Initialize user data in Firestore
  initializeUserData: async function(userId) {
    if (!this.db) {
      const initialized = this.init();
      if (!initialized) {
        console.error("Failed to initialize Firestore for user data initialization");
        return false;
      }
    }
    
    try {
      // Check if user stats document exists
      const statsRef = this.db.collection('user_stats').doc(userId);
      const statsDoc = await statsRef.get();
      
      // Create default user stats if it doesn't exist
      if (!statsDoc.exists) {
        console.log("Creating default user stats for:", userId);
        await statsRef.set({
          totalScans: 0,
          threatsDetected: 0,
          safeUrls: 0,
          avgRiskScore: 0,
          scanGrowth: 0,
          threatGrowth: 0,
          safeGrowth: 0,
          riskGrowth: 0,
          lastUpdated: firebase.firestore.FieldValue.serverTimestamp()
        });
      }
      
      // Check if activity data exists
      const activityRef = this.db.collection('activity_data').doc(userId);
      const activityDoc = await activityRef.get();
      
      if (!activityDoc.exists) {
        console.log("Creating default activity data for:", userId);
        
        // Create empty data for the last 6 months
        const labels = [];
        const data = [];
        const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const today = new Date();
        
        for (let i = 5; i >= 0; i--) {
          const monthIndex = (today.getMonth() - i + 12) % 12;
          labels.push(monthNames[monthIndex]);
          data.push(0); // zero scans for each month
        }
        
        await activityRef.set({
          chartData: { labels, data },
          lastUpdated: firebase.firestore.FieldValue.serverTimestamp()
        });
      }
      
      // Check if risk distribution exists
      const riskRef = this.db.collection('risk_distribution').doc(userId);
      const riskDoc = await riskRef.get();
      
      if (!riskDoc.exists) {
        console.log("Creating default risk distribution for:", userId);
        await riskRef.set({
          lowRisk: 0,
          mediumRisk: 0,
          highRisk: 0,
          lastUpdated: firebase.firestore.FieldValue.serverTimestamp()
        });
      }
      
      return true;
    } catch (error) {
      console.error("Error initializing user data:", error);
      return false;
    }
  },
  
  // Get scan statistics for dashboard
  getDashboardStats: async function(userId) {
    if (!this.db) {
      const initialized = this.init();
      if (!initialized) {
        console.error("Firestore not initialized for getDashboardStats");
        return null;
      }
    }
    
    try {
      // Get user-specific stats from 'user_stats' collection
      const statsRef = this.db.collection('user_stats').doc(userId || 'global');
      const statsDoc = await statsRef.get();
      
      if (statsDoc.exists) {
        console.log("Retrieved dashboard stats:", statsDoc.data());
        
        // Get data with fallbacks for missing fields
        const data = statsDoc.data();
        
        // Handle missing/undefined fields and calculate them if needed
        if (data.totalScans > 0) {
          // Calculate threatsDetected if missing
          if (data.threatsDetected === undefined) {
            // Estimate ~30% of scans are threats if not defined
            data.threatsDetected = Math.round(data.totalScans * 0.3);
          }
          
          // Calculate safeUrls if missing (total - threats)
          if (data.safeUrls === undefined) {
            data.safeUrls = data.totalScans - data.threatsDetected;
          }
          
          // Ensure avgRiskScore is defined
          if (data.avgRiskScore === undefined) {
            // Use a default average risk score of 30% if not defined
            data.avgRiskScore = 30;
          }
        }
        
        return data;
      } else {
        console.log("No stats found, initializing with zeros");
        // For new users, return zeros instead of null
        return {
          totalScans: 0,
          threatsDetected: 0,
          safeUrls: 0,
          avgRiskScore: 0,
          scanGrowth: 0,
          threatGrowth: 0,
          safeGrowth: 0,
          riskGrowth: 0
        };
      }
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      return null;
    }
  },
  
  // Subscribe to real-time updates for dashboard stats
  subscribeToStats: function(userId, callback) {
    if (!this.db) {
      const initialized = this.init();
      if (!initialized) {
        console.error("Firestore not initialized for subscribeToStats");
        return null;
      }
    }
    
    try {
      // First, get the actual count of scans from the user's scans collection
      const scansRef = this.db.collection('users').doc(userId).collection('scans');
      
      // Set up real-time listener to respond to changes
      const unsubscribe = scansRef.onSnapshot(snapshot => {
        // Calculate metrics directly from scan data
        const totalScans = snapshot.size;
        
        // Count scans by risk level
        let threatsDetected = 0;
        let safeUrls = 0;
        let totalRiskScore = 0;
        
        snapshot.forEach(doc => {
          const data = doc.data();
          const riskScore = parseInt(data.riskScore) || 0;
          
          // Add to total risk score for average calculation
          totalRiskScore += riskScore;
          
          // Count threats (high risk, > 60) and safe URLs (low risk, < 30)
          if (riskScore > 60) {
            threatsDetected++;
          } else if (riskScore < 30) {
            // Only count URLs with risk score < 30 as safe
            safeUrls++;
          }
          // Medium risk URLs (30-60) are neither threats nor safe
        });
        
        // Calculate average risk score
        const avgRiskScore = totalScans > 0 ? Math.round(totalRiskScore / totalScans) : 0;
        
        console.log("Stats calculated from real-time data:", {
          totalScans, 
          threatsDetected, 
          safeUrls, 
          avgRiskScore,
          totalRiskScore
        });
        
        // Create stats object
        const stats = {
          totalScans: totalScans,
          threatsDetected: threatsDetected,
          safeUrls: safeUrls,
          avgRiskScore: avgRiskScore,
          scanGrowth: 0,
          threatGrowth: 0,
          safeGrowth: 0,
          riskGrowth: 0
        };
        
        // Update stats in Firestore for future reference
        this.db.collection('user_stats').doc(userId).set(stats, { merge: true })
          .then(() => console.log("Stats updated in Firestore"))
          .catch(error => console.error("Error updating stats:", error));
        
        // Call the callback with the calculated stats
        callback(stats);
      }, error => {
        console.error("Error in scan stats listener:", error);
        callback(null);
      });
      
      return unsubscribe;
    } catch (error) {
      console.error("Error in subscribeToStats:", error);
      return null;
    }
  },
  
  // Get the total scan count from the user's scans collection
  getTotalScanCount: async function(userId) {
    if (!this.db) {
      const initialized = this.init();
      if (!initialized) {
        console.error("Failed to initialize Firestore for getTotalScanCount");
        return 0;
      }
    }
    
    try {
      // Get the size of the scans collection
      const scansRef = this.db.collection('users').doc(userId).collection('scans');
      const scansSnapshot = await scansRef.get();
      console.log("Retrieved total scan count:", scansSnapshot.size);
      return scansSnapshot.size;
    } catch (error) {
      console.error("Error getting total scan count:", error);
      return 0;
    }
  },
  
  // Get recent analyses for dashboard
  getRecentAnalyses: async function(userId, limit = 5) {
    if (!this.db) this.init();
    if (!this.db) {
      console.error("Firestore not initialized");
      return [];
    }
    
    try {
      // Get recent analyses from 'analyses' collection, filtered by userId
      const query = userId 
        ? this.db.collection('analyses').where('userId', '==', userId).orderBy('timestamp', 'desc').limit(limit)
        : this.db.collection('analyses').orderBy('timestamp', 'desc').limit(limit);
      
      const snapshot = await query.get();
      
      if (snapshot.empty) {
        // Return empty array for new users
        return [];
      }
      
      return snapshot.docs.map(doc => {
        const data = doc.data();
        return {
          id: doc.id,
          url: data.url,
          riskScore: data.riskScore,
          timestamp: data.timestamp.toDate ? data.timestamp.toDate() : data.timestamp,
          status: data.status || (data.riskScore < 30 ? 'Safe' : data.riskScore < 70 ? 'Suspicious' : 'Fraudulent')
        };
      });
    } catch (error) {
      console.error("Error fetching recent analyses:", error);
      return [];
    }
  },
  
  // Subscribe to real-time updates for analyses
  subscribeToAnalyses: function(userId, limit = 3, callback) {
    if (!this.db) {
      const initialized = this.init();
      if (!initialized) {
        console.error("Firestore not initialized for subscribeToAnalyses");
        return null;
      }
    }
    
    console.log(`Setting up real-time subscription for analyses, userId: ${userId}, limit: ${limit}`);
    
    // Query the user's scans collection
    const query = this.db.collection('users').doc(userId).collection('scans')
      .orderBy('timestamp', 'desc')
      .limit(limit);
    
    // Set up the real-time listener
    const unsubscribe = query.onSnapshot((snapshot) => {
      if (snapshot.empty) {
        console.log("No analyses found for user:", userId);
        callback([]);
        return;
      }
      
      console.log(`Retrieved ${snapshot.size} analyses for user:`, userId);
      
      const analyses = snapshot.docs.map(doc => {
        const data = doc.data();
        
        // Determine risk level based on score
        let status = 'Low Risk';
        if (data.riskScore > 60) {
          status = 'High Risk';
        } else if (data.riskScore >= 30) {
          status = 'Medium Risk';
        }
        
        // Format the timestamp
        let timestamp;
        if (data.timestamp) {
          if (data.timestamp.toDate) {
            timestamp = data.timestamp.toDate();
          } else if (data.timestamp.seconds) {
            timestamp = new Date(data.timestamp.seconds * 1000);
          } else {
            timestamp = new Date(data.timestamp);
          }
        } else {
          timestamp = new Date();
        }
        
        return {
          id: doc.id,
          url: data.url || "Unknown URL",
          riskScore: data.riskScore || 0,
          timestamp: timestamp,
          status: data.status || status
        };
      });
      
      callback(analyses);
    }, (error) => {
      console.error("Error in analyses subscription:", error);
      callback([]);
    });
    
    return unsubscribe;
  },
  
  // Get activity data for chart
  getActivityData: async function(userId, months = 6) {
    if (!this.db) this.init();
    if (!this.db) {
      console.error("Firestore not initialized");
      return null;
    }
    
    try {
      // Get activity data for chart from 'activity_data' collection
      const activityRef = this.db.collection('activity_data').doc(userId || 'global');
      const activityDoc = await activityRef.get();
      
      if (activityDoc.exists) {
        return activityDoc.data().chartData;
      } else {
        // Return empty chart data for new users
        const labels = [];
        const data = [];
        
        // Create empty data for the last 6 months
        const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const today = new Date();
        
        for (let i = 5; i >= 0; i--) {
          const monthIndex = (today.getMonth() - i + 12) % 12;
          labels.push(monthNames[monthIndex]);
          data.push(0); // zero scans for each month
        }
        
        return { labels, data };
      }
    } catch (error) {
      console.error("Error fetching activity data:", error);
      return null;
    }
  },
  
  // Subscribe to activity chart data
  subscribeToActivityData: function(userId, callback) {
    if (!this.db) {
      const initialized = this.init();
      if (!initialized) {
        console.error("Firestore not initialized for subscribeToActivityData");
        return null;
      }
    }
    
    try {
      // Get the user's scans collection to calculate actual activity data
      const scansRef = this.db.collection('users').doc(userId).collection('scans')
        .orderBy('timestamp', 'desc');
      
      // Set up real-time listener
      const unsubscribe = scansRef.onSnapshot(snapshot => {
        console.log(`Processing ${snapshot.size} scans for activity data`);
        
        // Initialize data for the last 7 days
        const dailyCounts = {};
        const labels = [];
        
        // Create array for the last 7 days (labels) and initialize daily counts
        for (let i = 6; i >= 0; i--) {
          const date = new Date();
          date.setDate(date.getDate() - i);
          
          // Format as ISO date string and extract just the date part (YYYY-MM-DD)
          const dateStr = date.toISOString().split('T')[0];
          
          // Format date for display
          const formattedDate = date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric'
          });
          
          labels.push(formattedDate);
          dailyCounts[dateStr] = 0;
        }
        
        // Count scans for each day
        snapshot.forEach(doc => {
          const data = doc.data();
          if (!data.timestamp) return;
          
          let scanDate;
          if (data.timestamp.toDate) {
            scanDate = data.timestamp.toDate();
          } else if (data.timestamp.seconds) {
            scanDate = new Date(data.timestamp.seconds * 1000);
          } else {
            scanDate = new Date(data.timestamp);
          }
          
          // Convert to local date string in same format
          const scanDateStr = scanDate.toISOString().split('T')[0];
          
          // Increment count if the date is in our tracking period
          if (dailyCounts.hasOwnProperty(scanDateStr)) {
            dailyCounts[scanDateStr]++;
            console.log(`Found scan for date ${scanDateStr}, new count: ${dailyCounts[scanDateStr]}`);
          }
        });
        
        // Convert to array in the same order as labels
        const data = [];
        for (let i = 6; i >= 0; i--) {
          const date = new Date();
          date.setDate(date.getDate() - i);
          const dateStr = date.toISOString().split('T')[0];
          data.push(dailyCounts[dateStr] || 0);
        }
        
        // Reverse both arrays so oldest date is first
        const activityData = {
          labels: labels,
          data: data
        };
        
        console.log("Final activity data:", activityData);
        
        // Call the callback with the activity data
        callback(activityData);
        
        // Save to Firestore for next time
        this.db.collection('activity_data').doc(userId).set({
          chartData: activityData,
          lastUpdated: firebase.firestore.FieldValue.serverTimestamp()
        }).catch(error => {
          console.error("Error saving activity data:", error);
        });
      }, error => {
        console.error("Error getting scans for activity data:", error);
        
        // Create default data for the last 7 days
        const labels = [];
        const data = [0, 0, 0, 0, 0, 0, 0];
        
        for (let i = 6; i >= 0; i--) {
          const date = new Date();
          date.setDate(date.getDate() - i);
          
          // Format date as short month + day (e.g., Jan 1)
          labels.push(date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric'
          }));
        }
        
        const defaultData = { labels, data };
        console.log("Using default activity data due to error:", defaultData);
        callback(defaultData);
      });
      
      return unsubscribe;
    } catch (error) {
      console.error("Error in subscribeToActivityData:", error);
      return null;
    }
  },
  
  // Get risk distribution data for chart
  getRiskDistribution: async function(userId) {
    if (!this.db) this.init();
    if (!this.db) {
      console.error("Firestore not initialized");
      return null;
    }
    
    try {
      // Get risk distribution from 'risk_distribution' collection
      const riskRef = this.db.collection('risk_distribution').doc(userId || 'global');
      const riskDoc = await riskRef.get();
      
      if (riskDoc.exists) {
        return riskDoc.data();
      } else {
        // Return zero distribution for new users
        return {
          lowRisk: 0,
          mediumRisk: 0,
          highRisk: 0
        };
      }
    } catch (error) {
      console.error("Error fetching risk distribution:", error);
    return null;
  }
  },
  
  // Subscribe to risk distribution data
  subscribeToRiskDistribution: function(userId, callback) {
    if (!this.db) {
      const initialized = this.init();
      if (!initialized) {
        console.error("Firestore not initialized for subscribeToRiskDistribution");
        return null;
      }
    }
    
    try {
      // Use the scans collection to calculate real risk distribution
      const scansRef = this.db.collection('users').doc(userId).collection('scans');
      
      // Set up real-time listener
      const unsubscribe = scansRef.onSnapshot(snapshot => {
        // Initialize counters
        let lowRisk = 0;
        let mediumRisk = 0;
        let highRisk = 0;
        
        if (!snapshot.empty) {
          // Calculate actual distribution from scans
          snapshot.forEach(doc => {
            const riskScore = parseInt(doc.data().riskScore) || 0;
            
            if (riskScore < 30) {
              lowRisk++;
            } else if (riskScore <= 60) {
              mediumRisk++;
            } else {
              highRisk++;
            }
          });
          
          console.log("Risk distribution calculated from actual scans:", { lowRisk, mediumRisk, highRisk });
        } else {
          // If no scans are found, use a default distribution for demonstration purposes
          lowRisk = 0;
          mediumRisk = 0;
          highRisk = 0;
          console.log("No scans found, using zero counts for risk distribution");
        }
        
        // Call the callback with the distribution data
        const distributionData = { lowRisk, mediumRisk, highRisk };
        callback(distributionData);
        
        // Store the distribution in Firestore for future reference
        this.db.collection('risk_distribution').doc(userId).set({
          ...distributionData,
          lastUpdated: firebase.firestore.FieldValue.serverTimestamp()
        }).catch(error => {
          console.error("Error saving risk distribution:", error);
        });
      }, error => {
        console.error("Error in risk distribution listener:", error);
        
        // Provide fallback data if there's an error
        const fallbackData = { lowRisk: 0, mediumRisk: 0, highRisk: 0 };
        callback(fallbackData);
      });
      
      return unsubscribe;
    } catch (error) {
      console.error("Error in subscribeToRiskDistribution:", error);
      return null;
    }
  },
  
  // Add a new analysis result
  addAnalysis: async function(analysisData) {
    if (!this.db) this.init();
    if (!this.db) {
      console.error("Firestore not initialized");
      return false;
    }
    
    try {
      // Add timestamp if not provided
      if (!analysisData.timestamp) {
        analysisData.timestamp = firebase.firestore.FieldValue.serverTimestamp();
      }
      
      // Add current user ID if logged in
      const user = firebase.auth().currentUser;
      if (user) {
        analysisData.userId = user.uid;
      }
      
      // Add analysis to 'analyses' collection
      const docRef = await this.db.collection('analyses').add(analysisData);
      
      // Update dashboard stats
      await this.updateDashboardStats(analysisData);
      
      // Update activity chart data
      await this.updateActivityData(analysisData);
      
      // Update risk distribution data
      await this.updateRiskDistribution(analysisData);
      
      return docRef.id;
    } catch (error) {
      console.error("Error adding analysis:", error);
      return false;
    }
  },
  
  // Update dashboard stats after adding a new analysis
  updateDashboardStats: async function(result) {
    if (!this.db) {
      const initialized = this.init();
      if (!initialized) {
        console.error("Firestore not initialized for updateDashboardStats");
        return false;
      }
    }
    
    try {
      const userId = firebase.auth().currentUser?.uid || 'global';
      console.log("Updating dashboard stats for user:", userId);
      const statsRef = this.db.collection('user_stats').doc(userId);
      
      // Use transactions to update safely
      return await this.db.runTransaction(async (transaction) => {
        const doc = await transaction.get(statsRef);
        
        // Determine risk levels
        const isHighRisk = result.riskScore > 60;
        const isLowRisk = result.riskScore < 30;
        const status = isHighRisk ? 'Fraudulent' : (isLowRisk ? 'Safe' : 'Suspicious');
        
        if (!doc.exists) {
          // Create new stats document
          console.log("Creating new stats document with initial scan");
          transaction.set(statsRef, {
            totalScans: 1,
            threatsDetected: isHighRisk ? 1 : 0,
            safeUrls: isLowRisk ? 1 : 0, // Only count low risk as safe
            avgRiskScore: result.riskScore,
            scanGrowth: 0,
            threatGrowth: 0,
            safeGrowth: 0,
            riskGrowth: 0,
            lastUpdated: firebase.firestore.FieldValue.serverTimestamp()
          });
        } else {
          // Update existing stats
          const data = doc.data();
          console.log("Updating existing stats:", data);
          const newTotal = data.totalScans + 1;
          const newThreats = data.threatsDetected + (isHighRisk ? 1 : 0);
          const newSafe = data.safeUrls + (isLowRisk ? 1 : 0); // Only count low risk as safe
          
          // Calculate new average
          const newAvg = ((data.avgRiskScore * data.totalScans) + result.riskScore) / newTotal;
          
          transaction.update(statsRef, {
            totalScans: newTotal,
            threatsDetected: newThreats,
            safeUrls: newSafe,
            avgRiskScore: Math.round(newAvg),
            lastUpdated: firebase.firestore.FieldValue.serverTimestamp()
          });
          
          console.log("Stats updated: total scans now", newTotal);
        }
        
        // Also update global stats if this is a user-specific update
        if (userId !== 'global') {
          const globalStatsRef = this.db.collection('user_stats').doc('global');
          const globalDoc = await transaction.get(globalStatsRef);
          
          if (globalDoc.exists) {
            const globalData = globalDoc.data();
            const newTotal = globalData.totalScans + 1;
            const newThreats = globalData.threatsDetected + (isHighRisk ? 1 : 0);
            const newSafe = globalData.safeUrls + (isLowRisk ? 1 : 0); // Only count low risk as safe
            
            // Calculate new average
            const newAvg = ((globalData.avgRiskScore * globalData.totalScans) + result.riskScore) / newTotal;
            
            transaction.update(globalStatsRef, {
              totalScans: newTotal,
              threatsDetected: newThreats,
              safeUrls: newSafe,
              avgRiskScore: Math.round(newAvg),
              lastUpdated: firebase.firestore.FieldValue.serverTimestamp()
            });
            
            console.log("Global stats updated");
          } else {
            // Create global stats if they don't exist
            transaction.set(globalStatsRef, {
              totalScans: 1,
              threatsDetected: isHighRisk ? 1 : 0,
              safeUrls: isLowRisk ? 1 : 0, // Only count low risk as safe
              avgRiskScore: result.riskScore,
              scanGrowth: 0,
              threatGrowth: 0,
              safeGrowth: 0,
              riskGrowth: 0,
              lastUpdated: firebase.firestore.FieldValue.serverTimestamp()
            });
            
            console.log("Global stats created");
          }
        }
        
        return true;
      });
    } catch (error) {
      console.error("Error updating dashboard stats:", error);
      return false;
    }
  },

  // Update activity chart data after new analysis
  updateActivityData: async function(result) {
    if (!this.db) this.init();
    if (!this.db) {
      console.error("Firestore not initialized");
      return false;
    }
    
    try {
      const userId = firebase.auth().currentUser?.uid || 'global';
      const activityRef = this.db.collection('activity_data').doc(userId);
      
      // Get current month name
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const currentMonth = monthNames[new Date().getMonth()];
      
      // Update activity data
      return await this.db.runTransaction(async (transaction) => {
        const doc = await transaction.get(activityRef);
        
        if (!doc.exists) {
          // Create new activity data document with 6 months of data
          const labels = [];
          const data = [];
          
          // Create empty data for previous 5 months and 1 for current month
          for (let i = 5; i >= 0; i--) {
            const monthIndex = (new Date().getMonth() - i + 12) % 12; // Handle wrapping around to previous year
            labels.push(monthNames[monthIndex]);
            data.push(i === 0 ? 1 : 0); // 1 for current month, 0 for past months
          }
          
          transaction.set(activityRef, {
            chartData: { labels, data }
          });
        } else {
          // Update existing activity data
          const chartData = doc.data().chartData;
          const monthIndex = chartData.labels.indexOf(currentMonth);
          
          if (monthIndex >= 0) {
            // Current month exists in data, increment the count
            const newData = [...chartData.data];
            newData[monthIndex] += 1;
            
            transaction.update(activityRef, {
              'chartData.data': newData
            });
          } else {
            // Current month not in data, shift arrays and add new month
            const newLabels = [...chartData.labels.slice(1), currentMonth];
            const newData = [...chartData.data.slice(1), 1];
            
            transaction.update(activityRef, {
              'chartData.labels': newLabels,
              'chartData.data': newData
            });
          }
        }
        
        return true;
      });
    } catch (error) {
      console.error("Error updating activity data:", error);
      return false;
    }
  },

  // Update risk distribution after new analysis
  updateRiskDistribution: async function(result) {
    if (!this.db) this.init();
    if (!this.db) {
      console.error("Firestore not initialized");
      return false;
    }
    
    try {
      const userId = firebase.auth().currentUser?.uid || 'global';
      const riskRef = this.db.collection('risk_distribution').doc(userId);
      
      // Determine risk category
      let riskCategory;
      if (result.riskScore < 30) {
        riskCategory = 'lowRisk';
      } else if (result.riskScore <= 60) {
        riskCategory = 'mediumRisk';
      } else {
        riskCategory = 'highRisk';
      }
      
      // Update risk distribution
      return await this.db.runTransaction(async (transaction) => {
        const doc = await transaction.get(riskRef);
        
        if (!doc.exists) {
          // Create new risk distribution document
          const initialData = {
            lowRisk: 0,
            mediumRisk: 0,
            highRisk: 0
          };
          initialData[riskCategory] = 1;
          
          transaction.set(riskRef, initialData);
        } else {
          // Update existing risk distribution
          const data = doc.data();
          const updatedValue = data[riskCategory] + 1;
          
          const update = {};
          update[riskCategory] = updatedValue;
          
          transaction.update(riskRef, update);
        }
        
        return true;
      });
    } catch (error) {
      console.error("Error updating risk distribution:", error);
      return false;
    }
  },
};

// Add global objects for access in frontend
window.firebaseAuth = firebaseAuth; 
window.firestoreDb = firestoreDb;

// Initialize Firestore when the script loads
document.addEventListener('DOMContentLoaded', function() {
  console.log("DOM content loaded, initializing Firestore");
  setTimeout(() => {
    // Properly wait for Firebase Firestore to be available
    if (typeof firebase !== 'undefined' && typeof firebase.firestore === 'function') {
      console.log("Firestore is available, initializing");
      const initialized = firestoreDb.init();
      console.log("Firestore initialization result:", initialized);
      
      if (initialized) {
        // Initialize user data when a user logs in
        firebase.auth().onAuthStateChanged((user) => {
          console.log("Auth state changed, user:", user ? user.uid : "no user");
          
          if (user) {
            // Initialize user data in Firestore if it doesn't exist
            firestoreDb.initializeUserData(user.uid);
          }
        });
      }
    } else {
      console.error("Firestore is not available after timeout");
    }
  }, 1000); // Give Firebase some time to fully load
}); 