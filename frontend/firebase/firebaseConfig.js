// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyD4iOeFtD-hETA5-8qWh9wRk-PNdhVKj-E",
  authDomain: "fraudtest-23c54.firebaseapp.com",
  projectId: "fraudtest-23c54",
  storageBucket: "fraudtest-23c54.appspot.com",
  messagingSenderId: "265409594914",
  appId: "1:265409594914:web:e199246e50428971c32c7b"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

export { auth };
export default app; 