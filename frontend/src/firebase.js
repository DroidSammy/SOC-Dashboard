import { initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';

// TODO: Replace with your actual Firebase project configuration
// 1. Go to console.firebase.google.com
// 2. Create a project
// 3. Add a Web App and copy the config below
const firebaseConfig = {
  apiKey: "AIzaSyBvivQWARTxAh-Oip8rn6iiTBGXY6EOJG8",
  authDomain: "soc-dashboard-337ea.firebaseapp.com",
  projectId: "soc-dashboard-337ea",
  storageBucket: "soc-dashboard-337ea.firebasestorage.app",
  messagingSenderId: "1095164562575",
  appId: "1:1095164562575:web:ee47ad34b92a8a81e0f4fa"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
