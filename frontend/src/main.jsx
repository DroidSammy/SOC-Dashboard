import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import '../index.css';

import { GoogleOAuthProvider } from '@react-oauth/google';

const GOOGLE_CLIENT_ID = '502989177042-3mupnogvt59qh3e90d1psiunkiktq9vv.apps.googleusercontent.com'; // Placeholder, replace with real Client ID

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>
      <App />
    </GoogleOAuthProvider>
  </React.StrictMode>
);
