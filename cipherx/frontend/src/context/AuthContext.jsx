import React, { createContext, useContext, useState, useEffect } from 'react';
import {
  signIn as apiSignIn,
  signUp as apiSignUp,
  signInWithGoogle as apiGoogleSignIn,
  fetchUserQuota as apiFetchQuota
} from '../services/api';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('cipherx_user');
    try {
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [quota, setQuota] = useState({ used: 0, total: 3, remaining: 3 });
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authMode, setAuthMode] = useState('signin'); // 'signin' or 'signup'
  const [pricingModalOpen, setPricingModalOpen] = useState(false);

  const refreshQuota = async () => {
    const userIdentifier = user?.email || 'guest_user';
    const data = await apiFetchQuota(userIdentifier);
    if (data) {
      setQuota(data);
    }
  };

  useEffect(() => {
    refreshQuota();
  }, [user]);

  const handleSignIn = async (email, password) => {
    const res = await apiSignIn(email, password);
    if (res && res.user) {
      setUser(res.user);
      localStorage.setItem('cipherx_user', JSON.stringify(res.user));
      if (res.quota) setQuota(res.quota);
      setAuthModalOpen(false);
      return res.user;
    }
  };

  const handleGoogleSignIn = async (googleProfile) => {
    const res = await apiGoogleSignIn(googleProfile);
    if (res && res.user) {
      setUser(res.user);
      localStorage.setItem('cipherx_user', JSON.stringify(res.user));
      if (res.quota) setQuota(res.quota);
      setAuthModalOpen(false);
      return res.user;
    }
  };

  const handleSignUp = async (email, password, fullName) => {
    const res = await apiSignUp(email, password, fullName);
    if (res && res.user) {
      setUser(res.user);
      localStorage.setItem('cipherx_user', JSON.stringify(res.user));
      await refreshQuota();
      setAuthModalOpen(false);
      return res.user;
    }
  };

  const handleSignOut = () => {
    setUser(null);
    localStorage.removeItem('cipherx_user');
    refreshQuota();
  };

  const openAuth = (mode = 'signin') => {
    setAuthMode(mode);
    setAuthModalOpen(true);
  };

  const closeAuth = () => {
    setAuthModalOpen(false);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        quota,
        setQuota,
        refreshQuota,
        authModalOpen,
        authMode,
        setAuthMode,
        openAuth,
        closeAuth,
        handleSignIn,
        handleSignUp,
        handleGoogleSignIn,
        handleSignOut,
        pricingModalOpen,
        setPricingModalOpen,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
