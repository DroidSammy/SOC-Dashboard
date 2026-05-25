import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import '../index.css';

import { GoogleOAuthProvider } from '@react-oauth/google';

const GOOGLE_CLIENT_ID = '351486719131-0h8j4g4h4b0a4g3k3k1l1j1m0n2o3p4q.apps.googleusercontent.com'; // Placeholder, replace with real Client ID

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>
      <App />
    </GoogleOAuthProvider>
  </React.StrictMode>
);
